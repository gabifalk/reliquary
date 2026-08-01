/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "cmd_admin.h"
#include "cmd_session.h"
#include "session.h"
#include "tokenstore.h"
#include "crypto_op.h"
#include "openpgp_fpr.h"
#include "keygrip.h"
#include "keyfile.h"
#include "meta.h"
#include "hex.h"
#include "pin.h"
#include "keywrap.h"
#include "crypto.h"
#include "crypto_rsa.h"
#include "crypto_ec.h"
#include "secmem.h"
#include "log.h"
#include <gcrypt.h>
#include <gpg-error.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* ---- store config helpers ---- */

typedef struct {
	int serial;
	char *admin_pin_salt_hex;
	char *admin_pin_hash_hex;
} store_config_t;

static int
store_config_read(const char *store_path, store_config_t *cfg)
{
	char path[768];
	snprintf(path, sizeof(path), "%s/config", store_path);

	memset(cfg, 0, sizeof(*cfg));

	FILE *f = fopen(path, "rb");
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = malloc((size_t)len + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}
	fread(buf, 1, (size_t)len, f);
	buf[len] = '\0';
	fclose(f);

	gcry_sexp_t root;
	if (gcry_sexp_new(&root, buf, 0, 1) != 0) {
		free(buf);
		return -1;
	}
	free(buf);

	/* Extract serial */
	gcry_sexp_t node = gcry_sexp_find_token(root, "serial", 0);
	if (node) {
		size_t vlen = 0;
		const char *val = gcry_sexp_nth_data(node, 1, &vlen);
		if (val && vlen > 0) {
			char tmp[32];
			size_t n = vlen < sizeof(tmp) - 1
			    ? vlen : sizeof(tmp) - 1;
			memcpy(tmp, val, n);
			tmp[n] = '\0';
			cfg->serial = atoi(tmp);
		}
		gcry_sexp_release(node);
	}

	/* Extract admin-pin-salt */
	node = gcry_sexp_find_token(root, "admin-pin-salt", 0);
	if (node) {
		size_t vlen = 0;
		const char *val = gcry_sexp_nth_data(node, 1, &vlen);
		if (val && vlen > 0) {
			cfg->admin_pin_salt_hex = malloc(vlen + 1);
			if (cfg->admin_pin_salt_hex) {
				memcpy(cfg->admin_pin_salt_hex, val, vlen);
				cfg->admin_pin_salt_hex[vlen] = '\0';
			}
		}
		gcry_sexp_release(node);
	}

	/* Extract admin-pin-hash */
	node = gcry_sexp_find_token(root, "admin-pin-hash", 0);
	if (node) {
		size_t vlen = 0;
		const char *val = gcry_sexp_nth_data(node, 1, &vlen);
		if (val && vlen > 0) {
			cfg->admin_pin_hash_hex = malloc(vlen + 1);
			if (cfg->admin_pin_hash_hex) {
				memcpy(cfg->admin_pin_hash_hex, val, vlen);
				cfg->admin_pin_hash_hex[vlen] = '\0';
			}
		}
		gcry_sexp_release(node);
	}

	gcry_sexp_release(root);
	return 0;
}

static int
store_config_write(const char *store_path, const store_config_t *cfg)
{
	char path[768];
	snprintf(path, sizeof(path), "%s/config", store_path);

	gcry_sexp_t root;
	if (gcry_sexp_build(&root, NULL,
			    "(store-config"
			    " (serial %d)"
			    " (admin-pin-salt %s)"
			    " (admin-pin-hash %s))",
			    cfg->serial,
			    cfg->admin_pin_salt_hex
			    ? cfg->admin_pin_salt_hex : "",
			    cfg->admin_pin_hash_hex
			    ? cfg->admin_pin_hash_hex : "") != 0)
		return -1;

	size_t len = gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	char *text = malloc(len);
	if (!text) {
		gcry_sexp_release(root);
		return -1;
	}
	gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, text, len);
	gcry_sexp_release(root);

	FILE *f = fopen(path, "w");
	if (!f) {
		free(text);
		return -1;
	}
	fputs(text, f);
	fclose(f);
	free(text);
	return 0;
}

static void
store_config_free(store_config_t *cfg)
{
	free(cfg->admin_pin_salt_hex);
	free(cfg->admin_pin_hash_hex);
	memset(cfg, 0, sizeof(*cfg));
}

#define ADMIN_PIN_MAX_RETRIES 3

/*
 * Read/write the admin PIN retry counter, persisted at
 * <store_path>/admin-state as "(admin-state (retries N))". Missing file
 * reads back as a full retry count (e.g. before INIT_STORE has run, or on
 * an older store that predates this file).
 *
 * A malformed or unparseable file, or a retries value outside
 * [0, ADMIN_PIN_MAX_RETRIES], is treated as ADMIN_PIN_MAX_RETRIES (fail
 * open): a corrupt admin-state file must never permanently lock the store.
 * A legitimate 0 written by a prior decrement is still honored and still
 * locks.
 */
static int
admin_state_read(const char *store_path, int *retries)
{
	char path[768];
	snprintf(path, sizeof(path), "%s/admin-state", store_path);
	FILE *f = fopen(path, "rb");
	if (!f) { *retries = ADMIN_PIN_MAX_RETRIES; return 0; }
	char buf[128] = { 0 };
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	char *p = strstr(buf, "retries ");
	int val = ADMIN_PIN_MAX_RETRIES;
	if (p) {
		char *endptr = NULL;
		long v = strtol(p + 8, &endptr, 10);
		if (endptr != p + 8 && v >= 0 && v <= ADMIN_PIN_MAX_RETRIES)
			val = (int)v;
		/* else: unparseable or out-of-range -- fail open to max */
	}
	*retries = val;
	return 0;
}

static int
admin_state_write(const char *store_path, int retries)
{
	char path[768];
	snprintf(path, sizeof(path), "%s/admin-state", store_path);
	FILE *f = fopen(path, "wb");
	if (!f) return -1;
	fprintf(f, "(admin-state (retries %d))", retries);
	fclose(f);
	return 0;
}

/*
 * Verify admin PIN against stored hash in store config.
 * Returns 0 on success, -1 on PIN mismatch (or lockout), -2 if store not
 * initialized. A retry counter persisted at <store_path>/admin-state
 * throttles online brute force: after ADMIN_PIN_MAX_RETRIES consecutive
 * failures, even the correct PIN is rejected until an admin resets the
 * counter (currently only by successfully verifying before it hits zero,
 * i.e. there is no separate unlock path).
 */
static int
verify_admin_pin(const char *store_path, const char *pin)
{
	store_config_t cfg;
	if (store_config_read(store_path, &cfg) != 0)
		return -2;

	if (!cfg.admin_pin_salt_hex || !cfg.admin_pin_hash_hex) {
		store_config_free(&cfg);
		return -2;
	}

	int retries = ADMIN_PIN_MAX_RETRIES;
	admin_state_read(store_path, &retries);
	if (retries <= 0) {
		store_config_free(&cfg);
		return -1;
	}

	unsigned char salt[CRYPTO_KDF_SALT_LEN];
	size_t salt_len = 0;
	if (hex_decode(cfg.admin_pin_salt_hex, salt, sizeof(salt), &salt_len)
	    != 0 || salt_len != CRYPTO_KDF_SALT_LEN) {
		store_config_free(&cfg);
		return -2;
	}

	unsigned char stored_hash[CRYPTO_GCM_KEY_LEN];
	size_t hash_len = 0;
	if (hex_decode(cfg.admin_pin_hash_hex, stored_hash,
		       sizeof(stored_hash), &hash_len) != 0
	    || hash_len != CRYPTO_GCM_KEY_LEN) {
		store_config_free(&cfg);
		return -2;
	}

	unsigned char derived[CRYPTO_GCM_KEY_LEN];
	if (crypto_kdf_derive(pin, strlen(pin), salt, derived,
			      sizeof(derived)) != 0) {
		store_config_free(&cfg);
		return -2;
	}

	store_config_free(&cfg);

	/* Constant-time compare */
	int match = 1;
	for (size_t i = 0; i < CRYPTO_GCM_KEY_LEN; i++)
		match &= (derived[i] == stored_hash[i]);

	if (match) {
		if (admin_state_write(store_path, ADMIN_PIN_MAX_RETRIES) != 0)
			log_warn("warning: failed to persist admin PIN "
				 "retry counter reset");
		return 0;
	}
	/*
	 * A failed decrement would leave admin brute force unthrottled: at least
	 * make it noisy so the failure is not silent.
	 */
	if (admin_state_write(store_path, retries - 1) != 0)
		log_warn("warning: failed to persist admin PIN retry "
			 "counter (%d); lockout may not be enforced",
			 retries - 1);
	return -1;
}

/*
 * Allocate the next serial number from the store config.
 * Returns the newly assigned serial, or -1 on error.
 */
static int
next_serial(const char *store_path)
{
	store_config_t cfg;
	if (store_config_read(store_path, &cfg) != 0)
		return -1;

	int assigned = cfg.serial + 1;
	cfg.serial = assigned;

	if (store_config_write(store_path, &cfg) != 0) {
		store_config_free(&cfg);
		return -1;
	}

	store_config_free(&cfg);
	return assigned;
}

/* ---- command helpers ---- */

static char *
skip_spaces(char *s)
{
	while (*s == ' ')
		s++;
	return s;
}

static char *
next_token(char **line)
{
	char *start = skip_spaces(*line);
	if (!*start)
		return NULL;
	char *end = strchr(start, ' ');
	if (end) {
		*end = '\0';
		*line = end + 1;
	} else {
		*line = start + strlen(start);
	}
	return start;
}

/* ---- admin commands ---- */

/*
 * STORE_STATUS
 * Returns OK if store is initialized, GPG_ERR_NOT_INITIALIZED otherwise.
 */
gpg_error_t
cmd_store_status(assuan_context_t ctx, char *line)
{
	(void)line;
	session_t *sess = assuan_get_pointer(ctx);

	store_config_t cfg;
	if (store_config_read(sess->store_path, &cfg) != 0)
		return gpg_error(GPG_ERR_NOT_INITIALIZED);

	store_config_free(&cfg);
	return 0;
}

/*
 * INIT_STORE <admin-pin>
 * First-time store initialization. Fails if config already exists.
 */
gpg_error_t
cmd_init_store(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *admin_pin = skip_spaces(line);
	if (!*admin_pin)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	/* Fail if config already exists */
	char path[768];
	snprintf(path, sizeof(path), "%s/config", sess->store_path);
	FILE *f = fopen(path, "rb");
	if (f) {
		fclose(f);
		return gpg_error(GPG_ERR_DUP_VALUE);
	}

	/* Hash admin PIN */
	char *salt_hex = NULL, *hash_hex = NULL;
	if (pin_create_hash(admin_pin, strlen(admin_pin),
			    &salt_hex, &hash_hex) != 0)
		return gpg_error(GPG_ERR_GENERAL);

	store_config_t cfg = {
		.serial = 0,
		.admin_pin_salt_hex = salt_hex,
		.admin_pin_hash_hex = hash_hex,
	};

	int rc = store_config_write(sess->store_path, &cfg);
	free(salt_hex);
	free(hash_hex);

	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);

	if (admin_state_write(sess->store_path, ADMIN_PIN_MAX_RETRIES) != 0)
		log_warn("warning: failed to persist initial admin "
			 "PIN retry counter");

	return 0;
}

/*
 * CREATE_TOKEN <label> <pin> <admin-pin>
 * Creates an empty token (no keys). Keys are added later via WRITEKEY.
 */
gpg_error_t
cmd_create_token(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *rest = line;
	char *label = next_token(&rest);
	char *pin = next_token(&rest);
	char *admin_pin = next_token(&rest);

	if (!label || !pin || !admin_pin)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);

	int vrc = verify_admin_pin(sess->store_path, admin_pin);
	if (vrc == -2)
		return gpg_error(GPG_ERR_NOT_INITIALIZED);
	if (vrc != 0)
		return gpg_error(GPG_ERR_BAD_PIN);

	if (tokenstore_create(sess->store_path, label) != 0)
		return gpg_error(GPG_ERR_DUP_VALUE);

	char tpath[512], mpath[768];
	tokenstore_token_path(sess->store_path, label, tpath, sizeof(tpath));
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);

	if (keywrap_create(tpath, pin, strlen(pin)) != 0) {
		tokenstore_remove(sess->store_path, label);
		return gpg_error(GPG_ERR_GENERAL);
	}

	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char timestamp[64];
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);

	int serial = next_serial(sess->store_path);
	if (serial < 0) {
		tokenstore_remove(sess->store_path, label);
		return gpg_error(GPG_ERR_GENERAL);
	}

	token_meta_t m = {
		.version = META_VERSION,
		.serial_num = serial,
		.label = (char *)label,
		.created_at = timestamp,
		.pin_max_retries = 3,
	};
	int rc = meta_write(mpath, &m);

	if (rc != 0) {
		tokenstore_remove(sess->store_path, label);
		return gpg_error(GPG_ERR_GENERAL);
	}

	token_state_t st = { .pin_retries = 3, .disconnected = 0 };
	if (state_write(tpath, &st) != 0) {
		tokenstore_remove(sess->store_path, label);
		return gpg_error(GPG_ERR_GENERAL);
	}

	log_debug("CREATE_TOKEN token=%s -> ok", label);
	return 0;
}

/*
 * Build the comma-separated allowed-mechanism list for (algo, slot): the
 * default set from mechpolicy_default_set(), plus any caller-supplied
 * additions (a comma-separated dotted-token list) not already present in the
 * default set. additions may be NULL or empty, in which case the plain
 * default set is returned. Returns a malloc'd string (caller frees, via
 * free()), or NULL on allocation failure.
 */
static char *
mechpolicy_merge(const char *algo, int slot, const char *additions)
{
	const char *def = mechpolicy_default_set(algo, slot);

	size_t cap = strlen(def) + 1;
	char *result = malloc(cap);
	if (!result)
		return NULL;
	strcpy(result, def);

	if (!additions || !*additions)
		return result;

	char *dup = strdup(additions);
	if (!dup) {
		free(result);
		return NULL;
	}

	char *save = NULL;
	for (char *tok = strtok_r(dup, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;
		size_t tlen = strlen(tok);
		while (tlen > 0 && tok[tlen - 1] == ' ')
			tok[--tlen] = '\0';
		if (tlen == 0)
			continue;

		/* Skip if already present as a whole comma-separated field. */
		int present = 0;
		for (const char *p = result; *p;) {
			const char *q = strchr(p, ',');
			size_t seglen = q ? (size_t)(q - p) : strlen(p);
			if (seglen == tlen && strncmp(p, tok, tlen) == 0) {
				present = 1;
				break;
			}
			p = q ? q + 1 : p + seglen;
		}
		if (present)
			continue;

		size_t oldlen = strlen(result);
		size_t newcap = oldlen + (oldlen ? 1 : 0) + tlen + 1;
		char *grown = realloc(result, newcap);
		if (!grown) {
			free(dup);
			free(result);
			return NULL;
		}
		result = grown;
		if (oldlen)
			strcat(result, ",");
		strcat(result, tok);
	}
	free(dup);
	return result;
}

/*
 * Validate a private-key S-expression, PIN-encrypt it into the given slot's
 * key file, and update that slot's metadata (algorithm + public key).
 * Auto-detects the algorithm from the S-expression.  Does NOT create or
 * remove the token directory and does NOT touch session state.
 *
 * Also sets this slot's allowed_mechs metadata to mechpolicy_default_set()
 * for the detected (algo, slot), merged with additions (a comma-separated
 * dotted-token list; may be NULL/empty for just the default set).
 *
 * On success algo_out (>=64 bytes) receives the detected algorithm name.
 * Returns 0 on success, or a gpg_error_t on failure.
 */
gpg_error_t
store_key_into_slot(const char *store_path, const char *label, int slot,
		    const unsigned char *keydata, size_t keydata_len,
		    const unsigned char *mk, const char *additions,
		    char algo_out[64])
{
	if (slot < 0 || slot >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_INV_VALUE);

	gcry_sexp_t sexp = NULL;
	if (gcry_sexp_new(&sexp, keydata, keydata_len, 0) != 0)
		return gpg_error(GPG_ERR_BAD_KEY);

	/* Detect algorithm from the S-expression. */
	const char *algo = "rsa2048";
	gcry_sexp_t rsa_node = gcry_sexp_find_token(sexp, "rsa", 0);
	if (rsa_node) {
		gcry_sexp_t n_node = gcry_sexp_find_token(rsa_node, "n", 0);
		if (n_node) {
			gcry_mpi_t n = gcry_sexp_nth_mpi(n_node, 1,
							 GCRYMPI_FMT_USG);
			if (n) {
				unsigned int nbits = gcry_mpi_get_nbits(n);
				if (nbits < 2048) {
					gcry_mpi_release(n);
					gcry_sexp_release(n_node);
					gcry_sexp_release(rsa_node);
					gcry_sexp_release(sexp);
					return gpg_error(GPG_ERR_NOT_SUPPORTED);
				} else if (nbits <= 2048)
					algo = "rsa2048";
				else if (nbits <= 3072)
					algo = "rsa3072";
				else
					algo = "rsa4096";
				gcry_mpi_release(n);
			}
			gcry_sexp_release(n_node);
		}
		gcry_sexp_release(rsa_node);
	} else {
		gcry_sexp_t ecc = gcry_sexp_find_token(sexp, "ecc", 0);
		if (!ecc) {
			gcry_sexp_release(sexp);
			return gpg_error(GPG_ERR_NOT_SUPPORTED);
		}
		gcry_sexp_t curve = gcry_sexp_find_token(ecc, "curve", 0);
		size_t clen = 0;
		const char *cname = curve
		    ? gcry_sexp_nth_data(curve, 1, &clen) : NULL;
		if (cname && clen == 10
		    && strncmp(cname, "NIST P-256", 10) == 0)
			algo = "nistp256";
		else if (cname && clen == 10
			 && strncmp(cname, "NIST P-384", 10) == 0)
			algo = "nistp384";
		else if (cname && clen == 10
			 && strncmp(cname, "NIST P-521", 10) == 0)
			algo = "nistp521";
		else if (cname && clen == 7
			 && strncmp(cname, "Ed25519", 7) == 0)
			algo = "ed25519";
		else {
			/*
			 * Unknown or unsupported curve (e.g. Ed448): reject
			 * rather than silently storing it under the wrong
			 * algorithm.
			 */
			gcry_sexp_release(curve);
			gcry_sexp_release(ecc);
			gcry_sexp_release(sexp);
			return gpg_error(GPG_ERR_NOT_SUPPORTED);
		}
		gcry_sexp_release(curve);
		gcry_sexp_release(ecc);
	}

	/*
	 * OpenPGP key creation time: gpg's WRITEKEY S-expression carries it as
	 * (created-at <unix-seconds>).  Needed for the v4 fingerprint and shown
	 * by gpg --card-status; absent for keys imported by other means.
	 */
	uint32_t created = 0;
	char created_str[32];
	created_str[0] = '\0';
	gcry_sexp_t ca = gcry_sexp_find_token(sexp, "created-at", 0);
	if (ca) {
		size_t dl = 0;
		const char *dv = gcry_sexp_nth_data(ca, 1, &dl);
		if (dv && dl > 0 && dl < sizeof(created_str)) {
			memcpy(created_str, dv, dl);
			created_str[dl] = '\0';
			created = (uint32_t)strtoul(created_str, NULL, 10);
		}
		gcry_sexp_release(ca);
	}

	/*
	 * Serialize to canonical form for storage.  This is the private key in
	 * the clear, so hold it in locked secure memory (freed via secure_free
	 * below) rather than swappable heap.
	 */
	size_t canon_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
	unsigned char *canon = secure_alloc(canon_len);
	if (!canon) {
		gcry_sexp_release(sexp);
		return gpg_error(GPG_ERR_ENOMEM);
	}
	canon_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, canon, canon_len);
	gcry_sexp_release(sexp);

	/* Extract public key. */
	unsigned char *pubkey = NULL;
	size_t pubkey_len = 0;
	int rc;
	if (strncmp(algo, "rsa", 3) == 0)
		rc = crypto_rsa_extract_pubkey(canon, canon_len, &pubkey,
					       &pubkey_len);
	else
		rc = crypto_ec_extract_pubkey(canon, canon_len, &pubkey,
					      &pubkey_len);
	if (rc != 0) {
		secure_free(canon, canon_len);
		return gpg_error(GPG_ERR_BAD_KEY);
	}

	/*
	 * Reject keys whose keygrip cannot be computed. gcry_pk_get_keygrip()
	 * abort()s on some malformed public keys; validating here (fork-guarded)
	 * keeps such a key out of the store, so the read path (GET_ATTRIBUTE
	 * keygrip / LIST_KEYS -> compute_keygrip) never runs into that abort.
	 */
	if (keygrip_computable(pubkey, pubkey_len) != 0) {
		free(pubkey);
		secure_free(canon, canon_len);
		return gpg_error(GPG_ERR_BAD_KEY);
	}

	static const char *slot_key_names[] = {
		"sign.key.enc", "encrypt.key.enc", "auth.key.enc"
	};
	char tpath[512], kpath[768], mpath[768];
	tokenstore_token_path(store_path, label, tpath, sizeof(tpath));
	snprintf(kpath, sizeof(kpath), "%s/%s", tpath, slot_key_names[slot]);
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);

	rc = keyfile_seal(kpath, mk, canon, canon_len);
	secure_free(canon, canon_len);
	if (rc != 0) {
		free(pubkey);
		return gpg_error(GPG_ERR_GENERAL);
	}

	/*
	 * Derive the OpenPGP v4 fingerprint from the freshly imported key so
	 * gpg --card-status shows a real fingerprint (and can bind General key
	 * info) instead of [none].
	 */
	char fpr_hex[41];
	int have_fpr = created
	    && openpgp_v4_fpr(algo, slot, created, pubkey, pubkey_len,
			      fpr_hex, sizeof(fpr_hex)) == 0;

	char *pub_hex = hex_encode(pubkey, pubkey_len);
	free(pubkey);

	/* Read existing metadata (if any) and update just this slot. */
	token_meta_t m = { 0 };
	int new_token = 0;
	if (meta_read(mpath, &m) != 0) {
		m.version = META_VERSION;
		m.label = (char *)label;
		m.created_at = "imported";
		m.pin_max_retries = 3;
		new_token = 1;
	}
	char *merged_mechs = mechpolicy_merge(algo, slot, additions);

	free(m.algorithm[slot]);
	free(m.public_key_hex[slot]);
	free(m.allowed_mechs[slot]);
	m.algorithm[slot] = (char *)algo;
	m.public_key_hex[slot] = pub_hex;
	m.allowed_mechs[slot] = merged_mechs;
	if (have_fpr) {
		free(m.key_fpr_hex[slot]);
		m.key_fpr_hex[slot] = strdup(fpr_hex);
	}
	if (created_str[0]) {
		free(m.key_time[slot]);
		m.key_time[slot] = strdup(created_str);
	}
	rc = meta_write(mpath, &m);
	m.algorithm[slot] = NULL;
	m.public_key_hex[slot] = NULL;
	m.allowed_mechs[slot] = NULL;
	meta_free(&m);
	free(pub_hex);
	free(merged_mechs);
	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);

	if (new_token) {
		token_state_t st = { .pin_retries = 3, .disconnected = 0 };
		state_write(tpath, &st);
	}

	strncpy(algo_out, algo, 63);
	algo_out[63] = '\0';
	return 0;
}

/*
 * GENKEY <slot> <algorithm> [<additions>]
 * Generate a key in a specific slot. Requires OPEN_SESSION + LOGIN.
 * slot: 0=sign, 1=encrypt, 2=auth (or OPENPGP.1, OPENPGP.2, OPENPGP.3)
 * algorithm: rsa2048, rsa3072, rsa4096,
 *            nistp256, nistp384, nistp521, ed25519
 * additions: optional comma-separated dotted-token list merged into this slot's
 *            allowed-mechanism set on top of the algorithm/slot default.
 */
gpg_error_t
cmd_genkey(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);
	if (!sess->logged_in || !sess->mk)
		return gpg_error(GPG_ERR_NOT_INITIALIZED);

	char *rest = line;
	char *slot_str = next_token(&rest);
	char *algo = next_token(&rest);
	char *additions = next_token(&rest);

	if (!slot_str || !algo)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	int slot;
	if (strncmp(slot_str, "OPENPGP.", 8) == 0)
		slot = atoi(slot_str + 8) - 1;
	else
		slot = atoi(slot_str);
	if (slot < 0 || slot >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	unsigned char *key = NULL;
	size_t key_len = 0;
	int rc;

	if (strncmp(algo, "rsa", 3) == 0) {
		unsigned int nbits = (unsigned int)atoi(algo + 3);
		if (nbits != 2048 && nbits != 3072 && nbits != 4096)
			return gpg_error(GPG_ERR_NOT_SUPPORTED);
		rc = crypto_rsa_keygen(nbits, &key, &key_len);
	} else if (strcmp(algo, "nistp256") == 0) {
		rc = crypto_ec_keygen("NIST P-256", &key, &key_len);
	} else if (strcmp(algo, "nistp384") == 0) {
		rc = crypto_ec_keygen("NIST P-384", &key, &key_len);
	} else if (strcmp(algo, "nistp521") == 0) {
		rc = crypto_ec_keygen("NIST P-521", &key, &key_len);
	} else if (strcmp(algo, "ed25519") == 0) {
		rc = crypto_ec_keygen("Ed25519", &key, &key_len);
	} else {
		return gpg_error(GPG_ERR_NOT_SUPPORTED);
	}

	if (rc != 0) {
		secure_free(key, key_len);
		return gpg_error(GPG_ERR_GENERAL);
	}

	/*
	 * Persist through the shared store path -- it seals the key file,
	 * extracts and records the public key, and merges the slot's mechanism
	 * policy.  This is the same path IMPORT_SLOT uses, so a generated key
	 * and an imported key are stored identically and cannot drift.
	 * store_key_into_slot re-detects the algorithm from the key material;
	 * for our own freshly generated key that matches the requested algo.
	 */
	char algo_out[64];
	gpg_error_t serr = store_key_into_slot(sess->store_path,
					       sess->token_label, slot, key,
					       key_len, sess->mk, additions,
					       algo_out);
	secure_free(key, key_len);
	if (serr)
		return serr;

	/*
	 * Reload the freshly written key into the session so SIGN/DECRYPT work
	 * immediately.  store_key_into_slot is store-level and deliberately does
	 * not touch the session, so this step stays with the caller.
	 */
	static const char *slot_key_names[] = {
		"sign.key.enc", "encrypt.key.enc", "auth.key.enc"
	};
	char kpath[768];
	snprintf(kpath, sizeof(kpath), "%s/%s",
		 sess->token_dir, slot_key_names[slot]);
	if (sess->key[slot])
		secure_free(sess->key[slot], sess->key_len[slot]);
	sess->key[slot] = NULL;
	sess->key_len[slot] = 0;
	if (keyfile_open(kpath, sess->mk, &sess->key[slot],
			 &sess->key_len[slot]) == 0)
		strncpy(sess->algorithm[slot], algo_out,
			sizeof(sess->algorithm[slot]) - 1);

	log_debug("GENKEY token=%s slot=%d -> ok", sess->token_label, slot);
	return 0;
}

/*
 * IMPORT_SLOT <slot> [<additions>]
 * Store a caller-supplied private-key S-expression into a slot. The key is
 * sent out-of-band via INQUIRE KEYDATA (it exceeds the Assuan line limit).
 * Requires OPEN_SESSION + LOGIN. Mirrors GENKEY but imports an existing key
 * instead of generating one; the algorithm is auto-detected.
 * additions: optional comma-separated dotted-token list merged into this slot's
 *            allowed-mechanism set on top of the algorithm/slot default.
 */
gpg_error_t
cmd_import_slot(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *rest = line;
	char *slot_str = next_token(&rest);
	if (!slot_str)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	/*
	 * Copy the slot and additions tokens NOW, before ensure_logged_in()
	 * and the KEYDATA inquiry below: both may perform an assuan_inquire()
	 * (NEEDPIN, then KEYDATA) that reuses libassuan's ctx inbound line
	 * buffer, which `line` (and slot_str/rest) point into -- reading them
	 * afterwards would return corrupt data.
	 */
	char additions_buf[256];
	const char *additions = NULL;
	{
		char *a = next_token(&rest);
		if (a && *a) {
			snprintf(additions_buf, sizeof(additions_buf), "%s", a);
			additions = additions_buf;
		}
	}

	int slot;
	if (strncmp(slot_str, "OPENPGP.", 8) == 0)
		slot = atoi(slot_str + 8) - 1;
	else
		slot = atoi(slot_str);
	if (slot < 0 || slot >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	gpg_error_t lerr = ensure_logged_in(ctx, sess);
	if (lerr)
		return lerr;

	/* Receive the private-key S-expression out-of-band. */
	unsigned char *keydata = NULL;
	size_t keydata_len = 0;
	gpg_error_t err = assuan_inquire(ctx, "KEYDATA", &keydata,
					 &keydata_len, 65536);
	if (err)
		return err;

	char algo[64];
	err = store_key_into_slot(sess->store_path, sess->token_label, slot,
				  keydata, keydata_len, sess->mk, additions,
				  algo);
	secure_zero(keydata, keydata_len);
	free(keydata);
	if (err)
		return err;

	/*
	 * Reload the key into the session so SIGN/DECRYPT work immediately.
	 * This also re-reads the key file we just wrote and verifies it decrypts
	 * under MK: if it does not, the slot is unusable, so fail loudly rather
	 * than reporting success and leaving a token no login can open.
	 */
	if (sess->key[slot])
		secure_free(sess->key[slot], sess->key_len[slot]);
	sess->key[slot] = NULL;
	sess->key_len[slot] = 0;
	char kpath[768];
	snprintf(kpath, sizeof(kpath), "%s/%s", sess->token_dir,
		 (slot == 0 ? "sign.key.enc" :
		  slot == 1 ? "encrypt.key.enc" : "auth.key.enc"));
	if (keyfile_open(kpath, sess->mk, &sess->key[slot],
			 &sess->key_len[slot]) != 0)
		return gpg_error(GPG_ERR_GENERAL);
	strncpy(sess->algorithm[slot], algo,
		sizeof(sess->algorithm[slot]) - 1);

	log_debug("IMPORT_SLOT token=%s slot=%d -> ok", sess->token_label, slot);
	return 0;
}

/*
 * DELETE_TOKEN <label> <admin-pin>
 * Remove a token entirely.
 */
gpg_error_t
cmd_delete_token(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *rest = line;
	char *label = next_token(&rest);
	char *admin_pin = next_token(&rest);

	if (!label || !admin_pin)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);

	int vrc = verify_admin_pin(sess->store_path, admin_pin);
	if (vrc == -2)
		return gpg_error(GPG_ERR_NOT_INITIALIZED);
	if (vrc != 0)
		return gpg_error(GPG_ERR_BAD_PIN);

	/* If deleting the currently open token, close the session */
	if (sess->token_label[0] && strcmp(sess->token_label, label) == 0)
		session_close(sess);

	if (tokenstore_remove(sess->store_path, label) != 0)
		return gpg_error(GPG_ERR_NOT_FOUND);

	log_debug("DELETE_TOKEN token=%s -> ok", label);
	return 0;
}

/*
 * CLEAR_TOKEN <label> <admin-pin>
 * Wipe key slots, keep token shell.
 */
gpg_error_t
cmd_clear_token(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *rest = line;
	char *label = next_token(&rest);
	char *admin_pin = next_token(&rest);

	if (!label || !admin_pin)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);

	int vrc = verify_admin_pin(sess->store_path, admin_pin);
	if (vrc == -2)
		return gpg_error(GPG_ERR_NOT_INITIALIZED);
	if (vrc != 0)
		return gpg_error(GPG_ERR_BAD_PIN);

	char tpath[512];
	tokenstore_token_path(sess->store_path, label, tpath, sizeof(tpath));

	/* Remove key files */
	static const char *slot_key_names[] = {
		"sign.key.enc", "encrypt.key.enc", "auth.key.enc"
	};
	for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
		char kpath[768];
		snprintf(kpath, sizeof(kpath), "%s/%s",
			 tpath, slot_key_names[i]);
		unlink(kpath);
	}

	/* Clear per-slot metadata */
	char mpath[768];
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	token_meta_t m = { 0 };
	if (meta_read(mpath, &m) != 0)
		return gpg_error(GPG_ERR_NOT_FOUND);

	for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
		free(m.algorithm[i]);
		m.algorithm[i] = NULL;
		free(m.public_key_hex[i]);
		m.public_key_hex[i] = NULL;
		free(m.key_fpr_hex[i]);
		m.key_fpr_hex[i] = NULL;
		free(m.key_time[i]);
		m.key_time[i] = NULL;
	}

	int rc = meta_write(mpath, &m);
	meta_free(&m);

	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);

	/* If clearing the currently open token, logout */
	if (sess->token_label[0] && strcmp(sess->token_label, label) == 0
	    && sess->logged_in)
		session_logout(sess);

	log_debug("CLEAR_TOKEN token=%s -> ok", label);
	return 0;
}

/*
 * DISCONNECT_TOKEN <label>
 * Hide token from enumeration by setting disconnected in state file.
 * No PIN required.
 */
gpg_error_t
cmd_disconnect_token(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *label = skip_spaces(line);
	if (!*label)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);

	if (!tokenstore_exists(sess->store_path, label))
		return gpg_error(GPG_ERR_NOT_FOUND);

	char tpath[512];
	tokenstore_token_path(sess->store_path, label, tpath, sizeof(tpath));

	token_state_t st = { .pin_retries = -1, .disconnected = 0 };
	state_read(tpath, &st);
	st.disconnected = 1;
	if (state_write(tpath, &st) != 0)
		return gpg_error(GPG_ERR_GENERAL);

	/* If disconnecting the currently open token, close the session */
	if (sess->token_label[0] && strcmp(sess->token_label, label) == 0)
		session_close(sess);

	return 0;
}

/*
 * CONNECT_TOKEN <label>
 * Make token visible again by clearing disconnected in state file.
 * No PIN required.
 */
gpg_error_t
cmd_connect_token(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	char *label = skip_spaces(line);
	if (!*label)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);

	if (!tokenstore_exists(sess->store_path, label))
		return gpg_error(GPG_ERR_NOT_FOUND);

	char tpath[512];
	tokenstore_token_path(sess->store_path, label, tpath, sizeof(tpath));

	token_state_t st = { .pin_retries = -1, .disconnected = 0 };
	state_read(tpath, &st);
	st.disconnected = 0;
	if (state_write(tpath, &st) != 0)
		return gpg_error(GPG_ERR_GENERAL);

	return 0;
}
