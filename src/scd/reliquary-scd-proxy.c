/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "client.h"
#include "hex.h"
#include <assuan.h>
#include <gpg-error.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct proxy_state {
	assuan_context_t daemon_ctx;
	char setdata_hex[8192];	/* buffered SETDATA for PKSIGN/PKDECRYPT */
	char current_label[256];	/* label the daemon session is open on */
};

struct relay_ctx {
	assuan_context_t server;
};

static gpg_error_t
relay_data_cb(void *opaque, const void *data, size_t len)
{
	struct relay_ctx *rc = opaque;
	return assuan_send_data(rc->server, data, len);
}

static gpg_error_t
relay_status_cb(void *opaque, const char *line)
{
	struct relay_ctx *rc = opaque;
	const char *space = strchr(line, ' ');
	if (space) {
		char keyword[128];
		size_t klen = (size_t)(space - line);
		if (klen >= sizeof(keyword))
			klen = sizeof(keyword) - 1;
		memcpy(keyword, line, klen);
		keyword[klen] = '\0';
		return assuan_write_status(rc->server, keyword, space + 1);
	}
	return assuan_write_status(rc->server, line, "");
}

struct inquire_relay_ctx {
	assuan_context_t server;	/* gpg-agent side (pipe server) */
	assuan_context_t client;	/* daemon side (socket client) */
};

/*
 * Inquiry callback: when the daemon sends INQUIRE <keyword>,
 * relay it to gpg-agent, get the data, and send it back to the daemon.
 */
static gpg_error_t
relay_inquire_cb(void *opaque, const char *line)
{
	struct inquire_relay_ctx *ictx = opaque;
	unsigned char *data = NULL;
	size_t data_len = 0;

	/* Ask gpg-agent for the data */
	gpg_error_t err = assuan_inquire(ictx->server, line, &data, &data_len,
					 65536);
	if (err)
		return err;

	/* Send the data back to the daemon */
	err = assuan_send_data(ictx->client, data, data_len);
	free(data);
	return err;
}

static gpg_error_t
forward_to_daemon(assuan_context_t server_ctx, const char *cmd_name, char *args)
{
	struct proxy_state *state = assuan_get_pointer(server_ctx);
	struct relay_ctx rc = {.server = server_ctx };
	struct inquire_relay_ctx ictx = {
		.server = server_ctx,
		.client = state->daemon_ctx
	};
	char full_cmd[1024];
	if (args && *args)
		snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd_name, args);
	else
		snprintf(full_cmd, sizeof(full_cmd), "%s", cmd_name);
	return assuan_transact(state->daemon_ctx, full_cmd,
			       relay_data_cb, &rc, relay_inquire_cb, &ictx,
			       relay_status_cb, &rc);
}

/* One row of LIST_TOKENS's "S TOKEN <serial> <label> <connected|disconnected>". */
struct token_row {
	char serial[64];
	char label[256];
	int connected;
};

struct token_scan {
	struct token_row rows[64];
	int n;
};

static gpg_error_t
token_scan_cb(void *opaque, const char *line)
{
	struct token_scan *s = opaque;
	if (s->n >= 64)
		return 0;
	char serial[64], label[256], status[32];
	if (sscanf(line, "TOKEN %63s %255s %31s", serial, label, status) < 3)
		return 0;
	snprintf(s->rows[s->n].serial, 64, "%s", serial);
	snprintf(s->rows[s->n].label, 256, "%s", label);
	s->rows[s->n].connected = (strcmp(status, "connected") == 0);
	s->n++;
	return 0;
}

/* Fill the scan from LIST_TOKENS. Returns 0 on success. */
static int
proxy_scan_tokens(assuan_context_t d, struct token_scan *s)
{
	s->n = 0;
	return client_command_status(d, "LIST_TOKENS", token_scan_cb, s) ? -1 : 0;
}

static gpg_error_t
proxy_open_label(struct proxy_state *st, const char *label)
{
	if (strcmp(st->current_label, label) == 0)
		return 0;
	char cmd[320];
	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", label);
	gpg_error_t e = client_command_ok(st->daemon_ctx, cmd);
	if (!e)
		snprintf(st->current_label, sizeof(st->current_label), "%s", label);
	return e;
}

static gpg_error_t
cmd_serialno(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	struct token_scan s;
	if (proxy_scan_tokens(state->daemon_ctx, &s) != 0)
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);

	/*
	 * Honor "SERIALNO --demand=<serial>": this is how `gpg --card-status
	 * all` selects each card in turn (g10/card-util.c card_status issues
	 * "SCD SERIALNO --demand=<serial>" per card, NOT SWITCHCARD).  Re-point
	 * the session at the demanded token, exactly like cmd_switchcard --
	 * otherwise the already-open card below is reported for every card and
	 * the same Application ID shows up once per reader.
	 */
	const char *demand = strstr(line, "--demand=");
	if (demand) {
		char want[64];
		demand += 9;	/* past "--demand=" */
		size_t i = 0;
		while (demand[i] && demand[i] != ' ' && i < sizeof(want) - 1) {
			want[i] = demand[i];
			i++;
		}
		want[i] = '\0';
		for (int j = 0; j < s.n; j++) {
			if (!s.rows[j].connected)
				continue;
			if (strcmp(s.rows[j].serial, want) != 0)
				continue;
			if (proxy_open_label(state, s.rows[j].label) != 0)
				return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
			assuan_write_status(ctx, "APPTYPE", "OPENPGP");
			assuan_write_status(ctx, "SERIALNO", s.rows[j].serial);
			return 0;
		}
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
	}

	/*
	 * If a token is already open (via a prior OPEN_SESSION/SWITCHCARD),
	 * report that one instead of jumping to the first connected token --
	 * SERIALNO must reflect whichever card is currently selected, not
	 * silently override an explicit selection.  Only fall back to
	 * auto-opening the first connected token when nothing is open yet.
	 */
	if (state->current_label[0]) {
		for (int i = 0; i < s.n; i++) {
			if (!s.rows[i].connected)
				continue;
			if (strcmp(s.rows[i].label, state->current_label) != 0)
				continue;
			assuan_write_status(ctx, "APPTYPE", "OPENPGP");
			assuan_write_status(ctx, "SERIALNO", s.rows[i].serial);
			return 0;
		}
	}

	for (int i = 0; i < s.n; i++) {
		if (!s.rows[i].connected)
			continue;
		if (proxy_open_label(state, s.rows[i].label) != 0)
			continue;
		assuan_write_status(ctx, "APPTYPE", "OPENPGP");
		assuan_write_status(ctx, "SERIALNO", s.rows[i].serial);
		return 0;
	}
	return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
}

/*
 * OpenPGP KEY-ATTR value for one slot. algorithm is "rsa2048"/"ed25519"/
 * "nistp256"/... or NULL/"" for an unpopulated slot (reported as RSA-2048).
 * Second field is the OpenPGP pubkey algo id: 1 RSA, 22 EdDSA, 19 ECDSA.
 */
static void
format_key_attr(int slot, const char *algorithm, char *out, size_t out_len)
{
	if (algorithm && algorithm[0]) {
		if (strncmp(algorithm, "rsa", 3) == 0) {
			int nbits = atoi(algorithm + 3);
			if (nbits == 0)
				nbits = 2048;
			snprintf(out, out_len, "%d 1 rsa%d 17 1", slot + 1, nbits);
		} else if (strcmp(algorithm, "ed25519") == 0) {
			snprintf(out, out_len, "%d 22 Ed25519", slot + 1);
		} else {
			snprintf(out, out_len, "%d 19 %s", slot + 1, algorithm);
		}
	} else {
		snprintf(out, out_len, "%d 1 rsa2048 17 1", slot + 1);
	}
}

/*
 * Fetch one D-line attribute of the current token into buf (NUL-terminated).
 * Returns 0 and sets *have=1 on data, 0 with *have=0 on NOT_FOUND, -1 on
 * error.
 */
static int
proxy_get_attr(assuan_context_t d, const char *attr, char *buf, size_t bufsz,
	       int *have)
{
	char *data = NULL;
	size_t len = 0;
	gpg_error_t e = client_command(d, attr, &data, &len);
	if (e) {
		*have = 0;
		free(data);
		/* NOT_FOUND is a normal "empty slot" signal, not a failure. */
		return (gpg_err_code(e) == GPG_ERR_NOT_FOUND) ? 0 : -1;
	}
	size_t n = len < bufsz - 1 ? len : bufsz - 1;
	memcpy(buf, data, n);
	buf[n] = '\0';
	free(data);
	*have = 1;
	return 0;
}

/*
 * Slot indices in a reliquary token (mirror RELIQUARY_SLOT_* in the daemon):
 * OpenPGP sign OPENPGP.1 -> 0, encrypt OPENPGP.2 -> 1, auth OPENPGP.3 -> 2.
 */
enum { PROXY_SLOT_SIGN = 0, PROXY_SLOT_ENCRYPT = 1, PROXY_SLOT_AUTH = 2 };

/*
 * Result of resolving a keygrip through the daemon's neutral LIST_KEYS.  The
 * daemon emits "S KEY <serial> <label> <slot> <keygrip> <fpr> <time> <algo>"
 * per key; we match on keygrip and keep the label (to OPEN_SESSION the daemon
 * onto that token) and the 0-based slot.
 */
struct grip_res {
	const char *want;	/* keygrip to match */
	char label[256];
	int slot;		/* 0-based */
	int found;
};

static gpg_error_t
grip_status_cb(void *opaque, const char *line)
{
	struct grip_res *r = opaque;
	if (r->found)
		return 0;
	char serial[64], label[256], grip[64];
	int slot = -1;
	if (sscanf(line, "KEY %63s %255s %d %63s", serial, label, &slot, grip) < 4)
		return 0;
	if (slot >= 0 && slot < 3 && strcmp(grip, r->want) == 0) {
		snprintf(r->label, sizeof(r->label), "%s", label);
		r->slot = slot;
		r->found = 1;
	}
	return 0;
}

static int
proxy_resolve_grip(assuan_context_t d, const char *grip,
		   char *label_out, size_t label_sz, int *slot_out)
{
	struct grip_res r = { .want = grip, .slot = -1 };
	if (client_command_status(d, "LIST_KEYS", grip_status_cb, &r) || !r.found)
		return -1;
	snprintf(label_out, label_sz, "%s", r.label);
	*slot_out = r.slot;
	return 0;
}

/*
 * Inquiry callback for the neutral SIGN/DECRYPT transaction.  The daemon raises
 * two kinds of inquiry inside one operation: NEEDPIN (login on demand), which we
 * RELAY to gpg-agent so its pinentry runs; and VALUE/CIPHERTEXT, which we answer
 * with the buffered SETDATA payload already decoded to raw bytes.
 */
struct crypto_inq_ctx {
	assuan_context_t server;	/* gpg-agent side (relay NEEDPIN here) */
	assuan_context_t daemon;	/* daemon side (answer here) */
	const unsigned char *payload;
	size_t payload_len;
};

static gpg_error_t
crypto_inq_cb(void *opaque, const char *line)
{
	struct crypto_inq_ctx *cc = opaque;
	if (strncmp(line, "NEEDPIN", 7) == 0) {
		unsigned char *data = NULL;
		size_t data_len = 0;
		gpg_error_t err = assuan_inquire(cc->server, line, &data,
						 &data_len, 65536);
		if (err)
			return err;
		err = assuan_send_data(cc->daemon, data, data_len);
		free(data);
		return err;
	}
	/* VALUE (SIGN) or CIPHERTEXT (DECRYPT): the raw payload from SETDATA. */
	return assuan_send_data(cc->daemon, cc->payload, cc->payload_len);
}

/*
 * Copy the last 40-char hex token on `line` into grip_out (needs 41 bytes);
 * grip_out is set to "" if the line carries no keygrip.  Must be called before
 * any inquiry, while `line` still points at valid inbound data.
 */
static void
extract_keygrip(const char *line, char *grip_out)
{
	grip_out[0] = '\0';
	const char *p = line;
	while (*p) {
		while (*p == ' ')
			p++;
		const char *tok = p;
		while (*p && *p != ' ')
			p++;
		if ((size_t)(p - tok) == 40) {
			int hex = 1;
			for (int i = 0; i < 40; i++)
				if (!isxdigit((unsigned char)tok[i])) {
					hex = 0;
					break;
				}
			if (hex) {
				memcpy(grip_out, tok, 40);
				grip_out[40] = '\0';
			}
		}
	}
}

/*
 * A slot has no usable OpenPGP fingerprint if the daemon returned nothing or an
 * empty/all-zero value.  gpg's scdaemon skips the KEY-FPR line in that case
 * (send_fpr_if_not_null); we must never substitute the keygrip, which is a
 * different SHA-1 (over the public-key S-expression, not the key packet) and
 * would make gpg fail to map the card key to its keyring key.
 */
static int
fpr_absent(const char *s)
{
	if (!s || !*s)
		return 1;
	for (; *s; s++)
		if (*s != '0')
			return 0;
	return 1;
}

static gpg_error_t
cmd_learn(assuan_context_t ctx, char *line)
{
	(void)line;
	struct proxy_state *state = assuan_get_pointer(ctx);
	assuan_context_t d = state->daemon_ctx;
	static const char *caps[] = { "sc", "e", "a" };

	/* SERIALNO/DISP-NAME header from the current token. */
	char serial[64], label[256];
	int have = 0;
	if (proxy_get_attr(d, "GET_ATTRIBUTE serial", serial, sizeof(serial),
			   &have) != 0 || !have)
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
	assuan_write_status(ctx, "APPTYPE", "OPENPGP");
	assuan_write_status(ctx, "SERIALNO", serial);
	if (proxy_get_attr(d, "GET_ATTRIBUTE label", label, sizeof(label),
			   &have) == 0 && have)
		assuan_write_status(ctx, "DISP-NAME", label);

	for (int i = 0; i < 3; i++) {
		char q[40], grip[64], fpr[128], tm[64], algo[64], st[256];
		int hg = 0, hf = 0, ht = 0, ha = 0;
		snprintf(q, sizeof(q), "GET_ATTRIBUTE keygrip.%d", i);
		proxy_get_attr(d, q, grip, sizeof(grip), &hg);
		if (!hg)
			continue;	/* empty slot */
		snprintf(st, sizeof(st), "%s OPENPGP.%d %s", grip, i + 1, caps[i]);
		assuan_write_status(ctx, "KEYPAIRINFO", st);

		snprintf(q, sizeof(q), "GET_ATTRIBUTE fpr.%d", i);
		proxy_get_attr(d, q, fpr, sizeof(fpr), &hf);
		if (hf && !fpr_absent(fpr)) {
			snprintf(st, sizeof(st), "%d %s", i + 1, fpr);
			assuan_write_status(ctx, "KEY-FPR", st);
		}

		snprintf(q, sizeof(q), "GET_ATTRIBUTE time.%d", i);
		proxy_get_attr(d, q, tm, sizeof(tm), &ht);
		snprintf(st, sizeof(st), "%d %s", i + 1, ht ? tm : "0");
		assuan_write_status(ctx, "KEY-TIME", st);

		snprintf(q, sizeof(q), "GET_ATTRIBUTE algorithm.%d", i);
		proxy_get_attr(d, q, algo, sizeof(algo), &ha);
		format_key_attr(i, ha ? algo : NULL, st, sizeof(st));
		assuan_write_status(ctx, "KEY-ATTR", st);
	}
	return 0;
}

static gpg_error_t
cmd_readkey(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	assuan_context_t d = state->daemon_ctx;

	char grip[41];
	extract_keygrip(line, grip);	/* copies out before any inquiry */
	int slot = -1;
	if (grip[0]) {
		char label[256];
		if (proxy_resolve_grip(d, grip, label, sizeof(label), &slot) == 0)
			proxy_open_label(state, label);
		else
			slot = -1;
	}
	if (slot < 0) {
		/* Fall back to OPENPGP.N form. */
		const char *p = line;
		while (*p == '-' || *p == ' ')
			p++;
		if (strncmp(p, "OPENPGP.", 8) == 0) {
			int n = atoi(p + 8);
			if (n >= 1 && n <= 3)
				slot = n - 1;
		}
	}
	if (slot < 0)
		return gpg_error(GPG_ERR_NO_PUBKEY);

	char q[40], hex[8192];
	int have = 0;
	snprintf(q, sizeof(q), "GET_ATTRIBUTE public_key.%d", slot);
	if (proxy_get_attr(d, q, hex, sizeof(hex), &have) != 0 || !have)
		return gpg_error(GPG_ERR_NO_PUBKEY);

	unsigned char raw[4096];
	size_t raw_len = 0;
	if (hex_decode(hex, raw, sizeof(raw), &raw_len) != 0)
		return gpg_error(GPG_ERR_GENERAL);
	return assuan_send_data(ctx, raw, raw_len);
}

/*
 * Translate gpg-agent's PKSIGN/PKAUTH/PKDECRYPT into the daemon's neutral
 * SIGN/DECRYPT.  Steps: resolve the keygrip to (label, slot) via LIST_KEYS and
 * point the daemon session at that token via OPEN_SESSION; pick the mechanism
 * (decrypt is always raw decrypt.rsa-raw, sign is per the slot's key algorithm);
 * decode the buffered SETDATA payload to raw bytes; issue SIGN/DECRYPT <slot>
 * <mech>, relaying NEEDPIN to gpg-agent and feeding the payload to the
 * VALUE/CIPHERTEXT inquiry; the raw result streams straight back to gpg-agent,
 * which wraps it.
 */
static gpg_error_t
translate_pk(assuan_context_t ctx, char *line, int is_decrypt, int default_slot)
{
	struct proxy_state *state = assuan_get_pointer(ctx);

	/*
	 * Snapshot the keygrip out of `line` BEFORE any inquiry: libassuan
	 * reuses the inbound line buffer for inquiry replies (a use-after-clobber
	 * hazard that has bitten this code repeatedly).
	 */
	char keygrip[41];
	extract_keygrip(line, keygrip);

	int slot = default_slot;
	if (keygrip[0]) {
		char label[256];
		int rslot = -1;
		if (proxy_resolve_grip(state->daemon_ctx, keygrip, label,
				       sizeof(label), &rslot) != 0)
			return gpg_error(GPG_ERR_NO_SECKEY);
		slot = rslot;
		gpg_error_t e = proxy_open_label(state, label);
		if (e)
			return e;
	}

	char mech[24];
	if (is_decrypt) {
		snprintf(mech, sizeof(mech), "decrypt.rsa-raw");
	} else {
		char attr[48];
		snprintf(attr, sizeof(attr), "GET_ATTRIBUTE algorithm.%d", slot);
		char *algo = NULL;
		size_t algo_len = 0;
		gpg_error_t e = client_command(state->daemon_ctx, attr,
					       &algo, &algo_len);
		if (e) {
			free(algo);
			return e;
		}
		/* client_command returns raw D-data (not NUL-terminated). */
		char algobuf[32];
		size_t n = algo_len < sizeof(algobuf) - 1
		    ? algo_len : sizeof(algobuf) - 1;
		if (algo)
			memcpy(algobuf, algo, n);
		algobuf[n] = '\0';
		free(algo);
		if (strncmp(algobuf, "rsa", 3) == 0)
			snprintf(mech, sizeof(mech), "sign.rsa-pkcs1");
		else if (strcmp(algobuf, "ed25519") == 0)
			snprintf(mech, sizeof(mech), "sign.eddsa");
		else
			snprintf(mech, sizeof(mech), "sign.ecdsa");
	}

	if (!state->setdata_hex[0])
		return gpg_error(GPG_ERR_MISSING_VALUE);
	unsigned char payload[4096];
	size_t payload_len = 0;
	int drc = hex_decode(state->setdata_hex, payload, sizeof(payload),
			     &payload_len);
	state->setdata_hex[0] = '\0';
	if (drc != 0)
		return gpg_error(GPG_ERR_INV_VALUE);

	struct relay_ctx rc = {.server = ctx };
	struct crypto_inq_ctx cc = {
		.server = ctx,
		.daemon = state->daemon_ctx,
		.payload = payload,
		.payload_len = payload_len,
	};
	char full[64];
	snprintf(full, sizeof(full), "%s %d %s",
		 is_decrypt ? "DECRYPT" : "SIGN", slot, mech);
	return assuan_transact(state->daemon_ctx, full,
			       relay_data_cb, &rc,
			       crypto_inq_cb, &cc, relay_status_cb, &rc);
}

static gpg_error_t
cmd_pksign(assuan_context_t ctx, char *line)
{
	return translate_pk(ctx, line, 0, PROXY_SLOT_SIGN);
}

static gpg_error_t
cmd_pkauth(assuan_context_t ctx, char *line)
{
	return translate_pk(ctx, line, 0, PROXY_SLOT_AUTH);
}

static gpg_error_t
cmd_pkdecrypt(assuan_context_t ctx, char *line)
{
	return translate_pk(ctx, line, 1, PROXY_SLOT_ENCRYPT);
}

static gpg_error_t
cmd_getattr(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	assuan_context_t d = state->daemon_ctx;
	char *attr = line;
	while (*attr == ' ')
		attr++;

	if (strcmp(attr, "APPTYPE") == 0)
		return assuan_write_status(ctx, "APPTYPE", "OPENPGP");
	if (strcmp(attr, "EXTCAP") == 0)
		return assuan_write_status(ctx, "EXTCAP",
			"gc=1+ki=1+fc=0+pd=0+mcl3=2048+aac=1+sm=0+si=0"
			"+dec=0+bt=0+kdf=0+ao=0");
	if (strcmp(attr, "CHV-STATUS") == 0)
		return assuan_write_status(ctx, "CHV-STATUS",
					   "1 127 127 127 3 0 3");
	if (strcmp(attr, "SERIALNO") == 0 || strcmp(attr, "DISP-NAME") == 0) {
		char buf[256];
		int have = 0;
		const char *q = strcmp(attr, "SERIALNO") == 0
		    ? "GET_ATTRIBUTE serial" : "GET_ATTRIBUTE label";
		if (proxy_get_attr(d, q, buf, sizeof(buf), &have) != 0 || !have)
			return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
		return assuan_write_status(ctx, attr, buf);
	}
	if (strcmp(attr, "KEY-FPR") == 0 || strcmp(attr, "KEY-TIME") == 0
	    || strcmp(attr, "KEY-ATTR") == 0) {
		/*
		 * KEY-ATTR and KEY-TIME intentionally emit for all 3 slots, each
		 * defaulting an unpopulated slot's value (RSA-2048 / "0").
		 * KEY-FPR is different:
		 * it is gated on the slot actually having a keygrip (populated),
		 * same as cmd_learn's KEY-FPR loop, and is emitted only when the
		 * slot has a real fingerprint -- never the keygrip, which is a
		 * different SHA-1 (see fpr_absent / cmd_learn).
		 * Do not "simplify" KEY-FPR to the all-slots pattern above.
		 */
		for (int i = 0; i < 3; i++) {
			char q[40], v[128], st[256];
			int have = 0;
			if (strcmp(attr, "KEY-ATTR") == 0) {
				snprintf(q, sizeof(q), "GET_ATTRIBUTE algorithm.%d", i);
				proxy_get_attr(d, q, v, sizeof(v), &have);
				format_key_attr(i, have ? v : NULL, st, sizeof(st));
				assuan_write_status(ctx, "KEY-ATTR", st);
				continue;
			}
			if (strcmp(attr, "KEY-FPR") == 0) {
				char grip[64];
				int hg = 0;
				snprintf(q, sizeof(q), "GET_ATTRIBUTE keygrip.%d", i);
				proxy_get_attr(d, q, grip, sizeof(grip), &hg);
				if (!hg)
					continue;	/* empty slot */
				snprintf(q, sizeof(q), "GET_ATTRIBUTE fpr.%d", i);
				proxy_get_attr(d, q, v, sizeof(v), &have);
				if (have && !fpr_absent(v)) {
					snprintf(st, sizeof(st), "%d %s",
						 i + 1, v);
					assuan_write_status(ctx, "KEY-FPR", st);
				}
				continue;
			}
			snprintf(q, sizeof(q), "GET_ATTRIBUTE time.%d", i);
			proxy_get_attr(d, q, v, sizeof(v), &have);
			if (!have)
				snprintf(v, sizeof(v), "0");
			snprintf(st, sizeof(st), "%d %s", i + 1, v);
			assuan_write_status(ctx, attr, st);
		}
		return 0;
	}
	if (attr[0] == '$') {
		int slot = -1;
		if (strcmp(attr, "$SIGNKEYID") == 0)
			slot = 0;
		else if (strcmp(attr, "$ENCRKEYID") == 0)
			slot = 1;
		else if (strcmp(attr, "$AUTHKEYID") == 0)
			slot = 2;
		if (slot >= 0) {
			char q[40], grip[64];
			int have = 0;
			snprintf(q, sizeof(q), "GET_ATTRIBUTE keygrip.%d", slot);
			if (proxy_get_attr(d, q, grip, sizeof(grip), &have) != 0
			    || !have)
				return gpg_error(GPG_ERR_NO_PUBKEY);
			return assuan_write_status(ctx, attr, grip);
		}
	}
	return 0;
}

static gpg_error_t
cmd_setattr(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	char *attr = line;
	while (*attr == ' ')
		attr++;

	if (strncmp(attr, "KEY-ATTR", 8) == 0)
		return 0;	/* algorithm is derived from the key, not set */

	const char *name = NULL;
	char *rest = NULL;
	if (strncmp(attr, "KEY-FPR", 7) == 0) {
		name = "KEY-FPR";
		rest = attr + 7;
	} else if (strncmp(attr, "KEY-TIME", 8) == 0) {
		name = "KEY-TIME";
		rest = attr + 8;
	} else {
		return gpg_error(GPG_ERR_NOT_SUPPORTED);
	}
	while (*rest == ' ')
		rest++;
	int slot_num = atoi(rest);	/* 1-based from gpg */
	if (slot_num < 1 || slot_num > 3)
		return 0;
	while (*rest && *rest != ' ')
		rest++;
	while (*rest == ' ')
		rest++;
	if (!*rest)
		return 0;

	char cmd[512];
	snprintf(cmd, sizeof(cmd), "SET_ATTRIBUTE %d %s %s",
		 slot_num - 1, name, rest);
	return client_command_ok(state->daemon_ctx, cmd);
}

/*
 * Does this WRITEKEY line target the OpenPGP encryption slot (OPENPGP.2)?
 * gpg's keytocard addresses the card slot by keyid; the encryption slot is
 * OPENPGP.2.  The line is "[--force] [--] <keyid> ...", matching the daemon's
 * cmd_writekey/parse_slot_ref parsing (skip --force, then any leading "--"
 * option terminator and spaces).
 */
static int
writekey_targets_encrypt(const char *line)
{
	const char *p = line;
	while (*p == ' ')
		p++;
	if (strncmp(p, "--force", 7) == 0)
		p += 7;
	/*
	 * Skip a leading "--" option terminator (GnuPG 2.5+ sends "-- OPENPGP.N")
	 * and any surrounding spaces, exactly as parse_slot_ref() does.
	 */
	while (*p == '-' || *p == ' ')
		p++;
	return strncmp(p, "OPENPGP.2", 9) == 0
	    && (p[9] == '\0' || p[9] == ' ');
}

static gpg_error_t
cmd_writekey(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);

	/*
	 * Parse [--force] [--] <OPENPGP.N> to a 0-based slot. Copy nothing
	 * across an inquiry -- we build the whole command before transacting.
	 */
	const char *p = line;
	while (*p == ' ')
		p++;
	if (strncmp(p, "--force", 7) == 0)
		p += 7;
	while (*p == '-' || *p == ' ')
		p++;
	int slot = 0;
	if (strncmp(p, "OPENPGP.", 8) == 0) {
		int n = atoi(p + 8);
		if (n >= 1 && n <= 3)
			slot = n - 1;
	}

	/*
	 * keytocard writes gpg's private encryption key into the card's
	 * encryption slot; gpg then decrypts via scd PKDECRYPT, which the daemon
	 * services as raw RSA (decrypt.rsa-raw).  Now that the daemon enforces the
	 * per-slot allowed set, the encrypt key must declare that raw mechanism
	 * or decryption is rejected.  Append it as the IMPORT_SLOT additions
	 * token for the encryption slot only -- sign/auth keys never do raw.
	 */
	char cmd[64];
	if (writekey_targets_encrypt(line))
		snprintf(cmd, sizeof(cmd), "IMPORT_SLOT %d decrypt.rsa-raw", slot);
	else
		snprintf(cmd, sizeof(cmd), "IMPORT_SLOT %d", slot);

	/*
	 * Relay NEEDPIN + KEYDATA inquiries to gpg-agent. relay_inquire_cb
	 * already forwards any daemon inquiry to gpg-agent and feeds the
	 * answer back, which covers both.
	 */
	struct relay_ctx rc = {.server = ctx };
	struct inquire_relay_ctx ictx = {.server = ctx, .client = state->daemon_ctx };
	return assuan_transact(state->daemon_ctx, cmd, relay_data_cb, &rc,
			       relay_inquire_cb, &ictx, relay_status_cb, &rc);
}

/*
 * KEYINFO [<grip>] enumerates keygrip -> serial + slot for gpg-agent's card
 * mapping, built from the daemon's neutral LIST_KEYS.  Format is
 * "S KEYINFO <grip> T <serial> OPENPGP.<n> - - - -"; the OpenPGP keyid is
 * 1-based while LIST_KEYS's slot is 0-based, hence the "slot + 1".
 */
struct keyinfo_emit {
	assuan_context_t out;	/* gpg-agent side */
	const char *filter;	/* keygrip filter, or NULL */
};

static gpg_error_t
keyinfo_emit_cb(void *opaque, const char *line)
{
	struct keyinfo_emit *e = opaque;
	char serial[64], label[256], grip[64];
	int slot = -1;
	if (sscanf(line, "KEY %63s %255s %d %63s", serial, label, &slot, grip) < 4)
		return 0;
	if (slot < 0 || slot > 2)
		return 0;
	if (e->filter && strcmp(grip, e->filter) != 0)
		return 0;
	char st[256];
	snprintf(st, sizeof(st), "%s T %s OPENPGP.%d - - - -",
		 grip, serial, slot + 1);
	return assuan_write_status(e->out, "KEYINFO", st);
}

static gpg_error_t
cmd_keyinfo(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	char *arg = line;
	while (*arg == ' ')
		arg++;
	while (*arg == '-') {		/* skip --list / --data */
		while (*arg && *arg != ' ')
			arg++;
		while (*arg == ' ')
			arg++;
	}
	struct keyinfo_emit e = { ctx, (*arg) ? arg : NULL };
	return client_command_status(state->daemon_ctx, "LIST_KEYS",
				     keyinfo_emit_cb, &e);
}

static gpg_error_t
cmd_checkpin(assuan_context_t ctx, char *line)
{
	(void)line;
	struct proxy_state *state = assuan_get_pointer(ctx);
	/*
	 * LOGIN with no inline PIN triggers NEEDPIN-on-demand on the daemon,
	 * which we relay to gpg-agent's pinentry.
	 */
	struct relay_ctx rc = {.server = ctx };
	struct inquire_relay_ctx ictx = {.server = ctx, .client = state->daemon_ctx };
	return assuan_transact(state->daemon_ctx, "LOGIN", relay_data_cb, &rc,
			       relay_inquire_cb, &ictx, relay_status_cb, &rc);
}

/*
 * SWITCHCARD [<serial>]: with no serial, report whichever token is currently
 * open (per current_label); with a serial, resolve it to a label via
 * LIST_TOKENS and select it through proxy_open_label, keeping current_label
 * accurate for later PKSIGN/PKAUTH/PKDECRYPT.
 */
static gpg_error_t
cmd_switchcard(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	char *arg = line;
	while (*arg == '-' || *arg == ' ')
		arg++;

	struct token_scan s;
	if (proxy_scan_tokens(state->daemon_ctx, &s) != 0)
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);

	if (!*arg) {
		/* No serial: report whichever token is currently open. */
		for (int i = 0; i < s.n; i++)
			if (strcmp(s.rows[i].label, state->current_label) == 0) {
				assuan_write_status(ctx, "SERIALNO",
						    s.rows[i].serial);
				return 0;
			}
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
	}
	for (int i = 0; i < s.n; i++) {
		if (strcmp(s.rows[i].serial, arg) != 0)
			continue;
		gpg_error_t e = proxy_open_label(state, s.rows[i].label);
		if (e)
			return e;
		assuan_write_status(ctx, "SERIALNO", s.rows[i].serial);
		return 0;
	}
	return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
}

/* Stubs for commands gpg-agent sends but we don't need to forward */
static gpg_error_t
cmd_nop(assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;
	return 0;
}

static gpg_error_t
cmd_setdata(assuan_context_t ctx, char *line)
{
	struct proxy_state *state = assuan_get_pointer(ctx);
	/*
	 * Buffer hex data for the next PKSIGN/PKDECRYPT.  gpg-agent splits a
	 * ciphertext that would exceed the Assuan line limit across several
	 * SETDATA lines: the first plain, the rest as "SETDATA --append <hex>".
	 * A 512-byte rsa4096 block (1024 hex chars) always triggers this, so we
	 * must honour --append and accumulate rather than overwrite -- otherwise
	 * only the final chunk (with a literal "--append" prefix) survives and
	 * hex_decode later rejects it.
	 */
	while (*line == ' ')
		line++;
	int append = 0;
	if (strncmp(line, "--append", 8) == 0
	    && (line[8] == ' ' || line[8] == '\0')) {
		append = 1;
		line += 8;
		while (*line == ' ')
			line++;
	}
	size_t cur = append ? strlen(state->setdata_hex) : 0;
	size_t len = strlen(line);
	if (cur + len >= sizeof(state->setdata_hex))
		return gpg_error(GPG_ERR_TOO_LARGE);
	memcpy(state->setdata_hex + cur, line, len + 1);
	return 0;
}

static gpg_error_t
cmd_restart(assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;
	return 0;
}

static char gpg_version[64] = "2.4.0";

static void
detect_gpg_version(void)
{
	FILE *fp = popen("gpgconf --version 2>/dev/null", "r");
	if (!fp)
		return;
	char line[256];
	if (fgets(line, sizeof(line), fp)) {
		/* "gpgconf (GnuPG) X.Y.Z" */
		const char *p = strrchr(line, ' ');
		if (p) {
			p++;
			size_t len = strlen(p);
			while (len > 0
			       && (p[len - 1] == '\n' || p[len - 1] == '\r'))
				len--;
			if (len > 0 && len < sizeof(gpg_version)) {
				memcpy(gpg_version, p, len);
				gpg_version[len] = '\0';
			}
		}
	}
	pclose(fp);
}

static gpg_error_t
cmd_getinfo(assuan_context_t ctx, char *line)
{
	if (strncmp(line, "version", 7) == 0)
		return assuan_send_data(ctx, gpg_version, strlen(gpg_version));
	if (strncmp(line, "pid", 3) == 0) {
		char buf[32];
		snprintf(buf, sizeof(buf), "%d", getpid());
		return assuan_send_data(ctx, buf, strlen(buf));
	}
	if (strncmp(line, "socket_name", 11) == 0)
		return gpg_error(GPG_ERR_NO_DATA);
	if (strncmp(line, "card_list", 9) == 0) {
		struct proxy_state *state = assuan_get_pointer(ctx);
		struct token_scan s;
		if (proxy_scan_tokens(state->daemon_ctx, &s) != 0)
			return 0;
		for (int i = 0; i < s.n; i++)
			if (s.rows[i].connected)
				assuan_write_status(ctx, "SERIALNO",
						    s.rows[i].serial);
		return 0;
	}
	return gpg_error(GPG_ERR_NOT_SUPPORTED);
}

static gpg_error_t
cmd_open_session(assuan_context_t ctx, char *line)
{
	/*
	 * Route through proxy_open_label rather than forwarding raw, so an
	 * external OPEN_SESSION (e.g. a caller selecting a token before running
	 * gpg operations) keeps state->current_label in sync with the daemon's
	 * actual session.  Without this, translate_pk's cache would go stale and
	 * re-issue a redundant OPEN_SESSION on the next PKSIGN/PKDECRYPT -- which
	 * resets the daemon's login state and breaks an already-logged-in
	 * session (session_open() always calls session_close()).
	 */
	struct proxy_state *state = assuan_get_pointer(ctx);
	char *label = line;
	while (*label == ' ')
		label++;
	if (!*label)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	return proxy_open_label(state, label);
}

static gpg_error_t
cmd_login(assuan_context_t ctx, char *line)
{
	return forward_to_daemon(ctx, "LOGIN", line);
}

static gpg_error_t
cmd_logout(assuan_context_t ctx, char *line)
{
	return forward_to_daemon(ctx, "LOGOUT", line);
}

static void
print_version(void)
{
	puts("reliquary-scd-proxy " RELIQUARY_VERSION);
}

static void
usage(void)
{
	puts("Usage: reliquary-scd-proxy\n"
	     "\n"
	     "gpg-agent's scdaemon backend for Reliquary. Not meant to be\n"
	     "run interactively: gpg-agent spawns it via the scdaemon-program\n"
	     "directive and speaks the Assuan scdaemon protocol over its\n"
	     "stdin/stdout. It connects to the running reliquary daemon.\n"
	     "\n"
	     "Options:\n"
	     "  -h, --help     show this help and exit\n"
	     "      --version  show version and exit");
}

int
main(int argc, char **argv)
{
	gpg_error_t err;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--version") == 0) {
			print_version();
			return 0;
		}
		if (strcmp(argv[i], "--help") == 0
		    || strcmp(argv[i], "-h") == 0) {
			usage();
			return 0;
		}
	}

	detect_gpg_version();

	struct proxy_state state = { 0 };
	if (client_connect(&state.daemon_ctx) != 0) {
		fprintf(stderr,
			"reliquary-scd-proxy: cannot connect to daemon\n");
		return 1;
	}

	assuan_context_t server_ctx;
	err = assuan_new(&server_ctx);
	if (err) {
		fprintf(stderr, "reliquary-scd-proxy: assuan_new: %s\n",
			gpg_strerror(err));
		client_disconnect(state.daemon_ctx);
		return 1;
	}

	assuan_fd_t fds[2] = {
		assuan_fdopen(0),	/* stdin */
		assuan_fdopen(1)	/* stdout */
	};
	err = assuan_init_pipe_server(server_ctx, fds);
	if (err) {
		fprintf(stderr, "reliquary-scd-proxy: pipe init: %s\n",
			gpg_strerror(err));
		assuan_release(server_ctx);
		client_disconnect(state.daemon_ctx);
		return 1;
	}

	assuan_set_hello_line(server_ctx, "Reliquary scdaemon proxy ready");
	assuan_set_pointer(server_ctx, &state);

	assuan_register_command(server_ctx, "SERIALNO", cmd_serialno, NULL);
	assuan_register_command(server_ctx, "LEARN", cmd_learn, NULL);
	assuan_register_command(server_ctx, "READKEY", cmd_readkey, NULL);
	assuan_register_command(server_ctx, "PKSIGN", cmd_pksign, NULL);
	assuan_register_command(server_ctx, "PKAUTH", cmd_pkauth, NULL);
	assuan_register_command(server_ctx, "PKDECRYPT", cmd_pkdecrypt, NULL);
	assuan_register_command(server_ctx, "GETATTR", cmd_getattr, NULL);
	assuan_register_command(server_ctx, "SETATTR", cmd_setattr, NULL);
	assuan_register_command(server_ctx, "WRITEKEY", cmd_writekey, NULL);
	assuan_register_command(server_ctx, "RESET", cmd_nop, NULL);
	assuan_register_command(server_ctx, "LOCK", cmd_nop, NULL);
	assuan_register_command(server_ctx, "UNLOCK", cmd_nop, NULL);
	assuan_register_command(server_ctx, "SWITCHCARD", cmd_switchcard, NULL);
	assuan_register_command(server_ctx, "SWITCHAPP", cmd_nop, NULL);
	assuan_register_command(server_ctx, "SETDATA", cmd_setdata, NULL);
	assuan_register_command(server_ctx, "CHECKPIN", cmd_checkpin, NULL);
	assuan_register_command(server_ctx, "RESTART", cmd_restart, NULL);
	assuan_register_command(server_ctx, "GETINFO", cmd_getinfo, NULL);
	assuan_register_command(server_ctx, "KEYINFO", cmd_keyinfo, NULL);
	assuan_register_command(server_ctx, "PASSWD", cmd_nop, NULL);
	assuan_register_command(server_ctx, "OPEN_SESSION", cmd_open_session,
				NULL);
	assuan_register_command(server_ctx, "LOGIN", cmd_login, NULL);
	assuan_register_command(server_ctx, "LOGOUT", cmd_logout, NULL);

	for (;;) {
		err = assuan_accept(server_ctx);
		if (gpg_err_code(err) == GPG_ERR_EOF
		    || err == (gpg_error_t) (-1))
			break;
		if (err)
			break;
		err = assuan_process(server_ctx);
		if (err)
			continue;
	}

	assuan_release(server_ctx);
	client_disconnect(state.daemon_ctx);
	return 0;
}
