/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "cmd_session.h"
#include "session.h"
#include "tokenstore.h"
#include "crypto_op.h"
#include "meta.h"
#include "keygrip.h"
#include "serial.h"
#include "secmem.h"
#include "log.h"
#include <gpg-error.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char *
skip_spaces(char *line)
{
	while (*line == ' ')
		line++;
	return line;
}

/* Check if the session's current token has been disconnected. */
static int
is_disconnected(session_t *sess)
{
	if (sess->token_label[0] == '\0')
		return 0;
	char tpath[512];
	tokenstore_token_path(sess->store_path, sess->token_label,
			      tpath, sizeof(tpath));
	token_state_t st;
	if (state_read(tpath, &st) == 0 && st.disconnected)
		return 1;
	return 0;
}

/* Auto-open the first available token if no session is active */
static gpg_error_t
auto_open(session_t * sess)
{
	if (sess->token_label[0] != '\0') {
		if (!is_disconnected(sess))
			return 0;
		session_close(sess);
	}
	char labels[64][256];
	int n = tokenstore_list(sess->store_path, labels, 64);
	if (n <= 0)
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
	if (session_open(sess, labels[0]) != 0)
		return gpg_error(GPG_ERR_CARD_NOT_PRESENT);
	return 0;
}

/*
 * Ensure the session is logged in, prompting for PIN via NEEDPIN inquiry
 * if needed.  Used by the neutral SIGN/DECRYPT/DERIVE handlers below (and by
 * IMPORT_SLOT in cmd_admin.c) so a caller that skips the explicit LOGIN
 * (e.g. the scd-proxy, which drives crypto entirely through those neutral
 * commands) still gets a PIN prompt on demand.  Declared in cmd_session.h so
 * both callers can reach it.
 */
gpg_error_t
ensure_logged_in(assuan_context_t ctx, session_t * sess)
{
	if (sess->logged_in)
		return 0;

	gpg_error_t err = auto_open(sess);
	if (err)
		return err;

	unsigned char *pin_data = NULL;
	size_t pin_buf_len = 0;
	err = assuan_inquire(ctx, "NEEDPIN ||Please enter the PIN",
			     &pin_data, &pin_buf_len, 256);
	if (err || !pin_data || pin_buf_len == 0) {
		free(pin_data);
		return gpg_error(GPG_ERR_BAD_PIN);
	}

	/* Use strlen -- gpg-agent pads with null bytes */
	size_t pin_data_len = strlen((const char *)pin_data);

	int rc = session_login(sess, (const char *)pin_data, pin_data_len);
	secure_zero(pin_data, pin_buf_len);
	free(pin_data);
	if (rc != 0)
		return gpg_error(rc == -2 ? GPG_ERR_PIN_BLOCKED
				 : GPG_ERR_BAD_PIN);

	return 0;
}

gpg_error_t
cmd_open_session(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);
	char *label = skip_spaces(line);
	if (!*label)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	if (!tokenstore_valid_label(label))
		return gpg_error(GPG_ERR_INV_NAME);
	int rc = session_open(sess, label);
	if (rc != 0)
		return gpg_error(GPG_ERR_NOT_FOUND);
	return 0;
}

gpg_error_t
cmd_close_session(assuan_context_t ctx, char *line)
{
	(void)line;
	session_t *sess = assuan_get_pointer(ctx);
	session_close(sess);
	return 0;
}

gpg_error_t
cmd_login(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);
	char *pin = skip_spaces(line);
	if (!*pin)
		return ensure_logged_in(ctx, sess);
	/*
	 * pin points into libassuan's inbound line buffer; wipe it once we are
	 * done so the cleartext PIN does not linger there (and cannot be paged
	 * to swap) for the rest of the connection.
	 */
	size_t pin_len = strlen(pin);
	int rc = session_login(sess, pin, pin_len);
	secure_zero(pin, pin_len);
	log_debug("LOGIN -> %s", rc == 0 ? "ok" : rc == -1 ? "wrong-pin" :
		  rc == -2 ? "locked" : "error");
	if (rc == -1)
		return gpg_error(GPG_ERR_BAD_PIN);
	if (rc == -2)
		return gpg_error(GPG_ERR_PIN_BLOCKED);
	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);
	return 0;
}

gpg_error_t
cmd_logout(assuan_context_t ctx, char *line)
{
	(void)line;
	session_t *sess = assuan_get_pointer(ctx);
	session_logout(sess);
	return 0;
}

gpg_error_t
cmd_sign(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	/*
	 * SIGN <slot> <mechanism> -- the data to sign travels out-of-band
	 * via INQUIRE VALUE (raw binary; does not reliably fit hex-encoded
	 * on one Assuan command line for large inputs).
	 */
	char *slot_str = skip_spaces(line);
	char *mech = strchr(slot_str, ' ');
	if (!mech)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	*mech++ = '\0';
	mech = skip_spaces(mech);

	int s = atoi(slot_str);
	if (s < 0 || s >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_NO_SECKEY);

	/*
	 * Copy the mechanism out of the line buffer before calling
	 * ensure_logged_in()/assuan_inquire() below -- both may perform an
	 * assuan_inquire() (NEEDPIN, then VALUE) that reuses that buffer, so
	 * a pointer into it (mech) would otherwise be left dangling into
	 * whatever the inquiry response overwrote it with.
	 */
	char mech_buf[64];
	snprintf(mech_buf, sizeof(mech_buf), "%s", mech);

	/*
	 * Not logged in yet (e.g. a caller that skipped LOGIN, such as the
	 * scd-proxy): prompt for the PIN via NEEDPIN now.  No-op if already
	 * logged in.
	 */
	gpg_error_t login_err = ensure_logged_in(ctx, sess);
	if (login_err)
		return login_err;

	if (!sess->key[s])
		return gpg_error(GPG_ERR_NO_SECKEY);

	unsigned char *data = NULL;
	size_t data_len = 0;
	gpg_error_t inq_err = assuan_inquire(ctx, "VALUE", &data,
					    &data_len, 65536);
	if (inq_err)
		return inq_err;

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	gpg_error_t op_err = op_sign(sess, s, mech_buf, data, data_len,
				     &sig, &sig_len);
	log_debug("SIGN slot=%d mech=%s -> %s", s, mech_buf,
		  op_err ? gpg_strerror(op_err) : "ok");
	log_debug2("SIGN in=%zu out=%zu bytes", data_len, sig_len);
	free(data);
	if (op_err)
		return op_err;

	gpg_error_t err = assuan_send_data(ctx, sig, sig_len);
	free(sig);
	return err;
}

gpg_error_t
cmd_decrypt(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	/*
	 * DECRYPT <slot> <mechanism> -- the ciphertext travels out-of-band via
	 * INQUIRE CIPHERTEXT (raw binary; a large ciphertext -- e.g. a 512-byte
	 * rsa4096 block, 1024 chars once hex-encoded -- does not reliably fit on
	 * one Assuan command line together with the slot/mechanism prefix).
	 */
	char *slot_str = skip_spaces(line);
	char *mech = strchr(slot_str, ' ');
	if (!mech)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	*mech++ = '\0';
	mech = skip_spaces(mech);

	int s = atoi(slot_str);
	if (s < 0 || s >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_NO_SECKEY);

	/*
	 * Copy the mechanism out of the line buffer before calling
	 * ensure_logged_in()/assuan_inquire() below -- both may perform an
	 * assuan_inquire() (NEEDPIN, then CIPHERTEXT) that reuses that
	 * buffer, so a pointer into it (mech) would otherwise be left
	 * dangling into whatever the inquiry response overwrote it with.
	 */
	char mech_buf[64];
	snprintf(mech_buf, sizeof(mech_buf), "%s", mech);

	/*
	 * Not logged in yet (e.g. a caller that skipped LOGIN, such as the
	 * scd-proxy): prompt for the PIN via NEEDPIN now.  No-op if already
	 * logged in.
	 */
	gpg_error_t login_err = ensure_logged_in(ctx, sess);
	if (login_err)
		return login_err;

	if (!sess->key[s])
		return gpg_error(GPG_ERR_NO_SECKEY);

	unsigned char *data = NULL;
	size_t data_len = 0;
	gpg_error_t inq_err = assuan_inquire(ctx, "CIPHERTEXT", &data,
					    &data_len, 65536);
	if (inq_err)
		return inq_err;

	unsigned char *pt = NULL;
	size_t pt_len = 0;
	gpg_error_t op_err = op_decrypt(sess, s, mech_buf, data, data_len,
					&pt, &pt_len);
	log_debug("DECRYPT slot=%d mech=%s -> %s", s, mech_buf,
		  op_err ? gpg_strerror(op_err) : "ok");
	log_debug2("DECRYPT in=%zu out=%zu bytes", data_len, pt_len);
	free(data);
	if (op_err)
		return op_err;

	gpg_error_t err = assuan_send_data(ctx, pt, pt_len);
	secure_free(pt, pt_len);
	return err;
}

gpg_error_t
cmd_derive(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);

	/*
	 * DERIVE <slot> <mechanism> -- the peer public key travels
	 * out-of-band via INQUIRE PEERKEY (raw binary; does not reliably
	 * fit hex-encoded on one Assuan command line for large inputs).
	 */
	char *slot_str = skip_spaces(line);
	char *mech = strchr(slot_str, ' ');
	if (!mech)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	*mech++ = '\0';
	mech = skip_spaces(mech);

	int s = atoi(slot_str);
	if (s < 0 || s >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_NO_SECKEY);

	/*
	 * Copy the mechanism out of the line buffer before calling
	 * ensure_logged_in()/assuan_inquire() below -- both may perform an
	 * assuan_inquire() (NEEDPIN, then PEERKEY) that reuses that buffer,
	 * so a pointer into it (mech) would otherwise be left dangling into
	 * whatever the inquiry response overwrote it with.
	 */
	char mech_buf[64];
	snprintf(mech_buf, sizeof(mech_buf), "%s", mech);

	/*
	 * Not logged in yet (e.g. a caller that skipped LOGIN, such as the
	 * scd-proxy): prompt for the PIN via NEEDPIN now.  No-op if already
	 * logged in.
	 */
	gpg_error_t login_err = ensure_logged_in(ctx, sess);
	if (login_err)
		return login_err;

	if (!sess->key[s])
		return gpg_error(GPG_ERR_NO_SECKEY);

	unsigned char *peer_pub = NULL;
	size_t peer_len = 0;
	gpg_error_t inq_err = assuan_inquire(ctx, "PEERKEY", &peer_pub,
					    &peer_len, 65536);
	if (inq_err)
		return inq_err;

	unsigned char *secret = NULL;
	size_t secret_len = 0;
	gpg_error_t op_err = op_derive(sess, s, mech_buf, peer_pub, peer_len,
				       &secret, &secret_len);
	log_debug("DERIVE slot=%d mech=%s -> %s", s, mech_buf,
		  op_err ? gpg_strerror(op_err) : "ok");
	log_debug2("DERIVE in=%zu out=%zu bytes", peer_len, secret_len);
	free(peer_pub);
	if (op_err)
		return op_err;

	gpg_error_t err = assuan_send_data(ctx, secret, secret_len);
	secure_free(secret, secret_len);
	return err;
}

gpg_error_t
cmd_list_tokens(assuan_context_t ctx, char *line)
{
	(void)line;
	session_t *sess = assuan_get_pointer(ctx);
	char labels[64][256];
	int n = tokenstore_list_all(sess->store_path, labels, 64);
	for (int i = 0; i < n; i++) {
		char tpath[512];
		tokenstore_token_path(sess->store_path, labels[i],
				      tpath, sizeof(tpath));
		token_state_t st;
		int disc = (state_read(tpath, &st) == 0 && st.disconnected);

		char mpath[768];
		snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
		token_meta_t m = { 0 };
		meta_read(mpath, &m);
		char serbuf[64];
		reliquary_format_serial(m.serial_num, serbuf, sizeof(serbuf));
		meta_free(&m);

		char sline[700];
		snprintf(sline, sizeof(sline), "%s %s %s", serbuf, labels[i],
			 disc ? "disconnected" : "connected");
		assuan_write_status(ctx, "TOKEN", sline);
	}
	return 0;
}

gpg_error_t
cmd_get_mechanism_list(assuan_context_t ctx, char *line)
{
	(void)line;
	char buf[256];
	mechpolicy_advertised(buf, sizeof(buf));
	return assuan_send_data(ctx, buf, strlen(buf));
}

gpg_error_t
cmd_list_keys(assuan_context_t ctx, char *line)
{
	(void)line;
	session_t *sess = assuan_get_pointer(ctx);
	char labels[64][256];
	int n = tokenstore_list(sess->store_path, labels, 64);
	for (int t = 0; t < n; t++) {
		char tpath[512], mpath[768];
		tokenstore_token_path(sess->store_path, labels[t],
				      tpath, sizeof(tpath));
		snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
		token_meta_t m = { 0 };
		if (meta_read(mpath, &m) != 0)
			continue;
		char serial[64];
		reliquary_format_serial(m.serial_num, serial, sizeof(serial));
		for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
			char grip[41];
			if (!m.public_key_hex[i]
			    || compute_keygrip(m.public_key_hex[i], grip,
					       sizeof(grip)) != 0)
				continue;
			const char *fpr = (m.key_fpr_hex[i] && m.key_fpr_hex[i][0])
			    ? m.key_fpr_hex[i] : "-";
			const char *tm = (m.key_time[i] && m.key_time[i][0])
			    ? m.key_time[i] : "-";
			const char *alg = (m.algorithm[i] && m.algorithm[i][0])
			    ? m.algorithm[i] : "-";
			char st[512];
			snprintf(st, sizeof(st), "%s %s %d %s %s %s %s",
				 serial, labels[t], i, grip, fpr, tm, alg);
			assuan_write_status(ctx, "KEY", st);
		}
		meta_free(&m);
	}
	return 0;
}

gpg_error_t
cmd_get_attribute(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);
	if (sess->token_label[0] == '\0')
		return gpg_error(GPG_ERR_NOT_INITIALIZED);

	char *attr = skip_spaces(line);
	char mpath[768];
	snprintf(mpath, sizeof(mpath), "%s/metadata", sess->token_dir);
	token_meta_t m = { 0 };
	if (meta_read(mpath, &m) != 0)
		return gpg_error(GPG_ERR_GENERAL);

	const char *val = NULL;
	if (strcmp(attr, "label") == 0)
		val = m.label;
	else if (strcmp(attr, "algorithm") == 0)
		val = m.algorithm[0];
	else if (strcmp(attr, "public_key") == 0)
		val = m.public_key_hex[0];
	else if (strcmp(attr, "created_at") == 0)
		val = m.created_at;
	else if (strncmp(attr, "algorithm.", 10) == 0) {
		int s = atoi(attr + 10);
		if (s >= 0 && s < RELIQUARY_NUM_SLOTS)
			val = m.algorithm[s];
	} else if (strncmp(attr, "public_key.", 11) == 0) {
		int s = atoi(attr + 11);
		if (s >= 0 && s < RELIQUARY_NUM_SLOTS)
			val = m.public_key_hex[s];
	} else if (strncmp(attr, "keygrip.", 8) == 0) {
		int s = atoi(attr + 8);
		char grip[41];
		if (s >= 0 && s < RELIQUARY_NUM_SLOTS && m.public_key_hex[s]
		    && compute_keygrip(m.public_key_hex[s], grip,
				       sizeof(grip)) == 0) {
			gpg_error_t e = assuan_send_data(ctx, grip, strlen(grip));
			meta_free(&m);
			return e;
		}
	} else if (strncmp(attr, "fpr.", 4) == 0) {
		int s = atoi(attr + 4);
		if (s >= 0 && s < RELIQUARY_NUM_SLOTS)
			val = m.key_fpr_hex[s];
	} else if (strncmp(attr, "time.", 5) == 0) {
		int s = atoi(attr + 5);
		if (s >= 0 && s < RELIQUARY_NUM_SLOTS)
			val = m.key_time[s];
	} else if (strcmp(attr, "serial") == 0) {
		char serbuf[64];
		reliquary_format_serial(m.serial_num, serbuf, sizeof(serbuf));
		gpg_error_t e = assuan_send_data(ctx, serbuf, strlen(serbuf));
		meta_free(&m);
		return e;
	}

	gpg_error_t err;
	if (val)
		err = assuan_send_data(ctx, val, strlen(val));
	else
		err = gpg_error(GPG_ERR_NOT_FOUND);

	meta_free(&m);
	return err;
}

gpg_error_t
cmd_set_attribute(assuan_context_t ctx, char *line)
{
	session_t *sess = assuan_get_pointer(ctx);
	if (sess->token_label[0] == '\0')
		return gpg_error(GPG_ERR_NOT_INITIALIZED);

	char *slot_str = skip_spaces(line);
	char *sp = strchr(slot_str, ' ');
	if (!sp)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	*sp = '\0';
	char *name = skip_spaces(sp + 1);
	char *sp2 = strchr(name, ' ');
	if (!sp2)
		return gpg_error(GPG_ERR_ASS_SYNTAX);
	*sp2 = '\0';
	char *value = skip_spaces(sp2 + 1);
	if (!*value)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	int slot = atoi(slot_str);
	if (slot < 0 || slot >= RELIQUARY_NUM_SLOTS)
		return gpg_error(GPG_ERR_ASS_SYNTAX);

	char mpath[768];
	snprintf(mpath, sizeof(mpath), "%s/metadata", sess->token_dir);
	token_meta_t m = { 0 };
	if (meta_read(mpath, &m) != 0) {
		meta_free(&m);
		return gpg_error(GPG_ERR_GENERAL);
	}

	char **field = NULL;
	if (strcmp(name, "KEY-FPR") == 0)
		field = &m.key_fpr_hex[slot];
	else if (strcmp(name, "KEY-TIME") == 0)
		field = &m.key_time[slot];
	if (!field) {
		meta_free(&m);
		return gpg_error(GPG_ERR_NOT_SUPPORTED);
	}

	free(*field);
	*field = strdup(value);
	if (!*field) {
		meta_free(&m);
		return gpg_error(GPG_ERR_GENERAL);
	}
	int wrc = meta_write(mpath, &m);
	meta_free(&m);
	return wrc == 0 ? 0 : gpg_error(GPG_ERR_GENERAL);
}
