/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "cmd_admin.h"
#include "session.h"
#include "tokenstore.h"
#include "meta.h"
#include "hex.h"
#include "pin.h"
#include "keywrap.h"
#include "crypto.h"
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
