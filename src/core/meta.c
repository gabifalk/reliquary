/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "meta.h"
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *
read_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *buf = malloc((size_t)len + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	fread(buf, 1, (size_t)len, f);
	buf[len] = '\0';
	fclose(f);
	return buf;
}

/* Extract a string value from an S-expression, with length. */
static char *
sexp_strdup(gcry_sexp_t root, const char *key)
{
	gcry_sexp_t node = gcry_sexp_find_token(root, key, 0);
	if (!node)
		return NULL;
	size_t len = 0;
	const char *val = gcry_sexp_nth_data(node, 1, &len);
	char *result = NULL;
	if (val && len > 0) {
		result = malloc(len + 1);
		if (result) {
			memcpy(result, val, len);
			result[len] = '\0';
		}
	}
	gcry_sexp_release(node);
	return result;
}

static int
sexp_int(gcry_sexp_t root, const char *key, int def)
{
	char *s = sexp_strdup(root, key);
	if (!s)
		return def;
	int val = atoi(s);
	free(s);
	return val;
}

static int
atomic_write(const char *path, const char *text)
{
	size_t path_len = strlen(path);
	char *tmp = malloc(path_len + 5);
	if (!tmp)
		return -1;
	snprintf(tmp, path_len + 5, "%s.tmp", path);

	FILE *f = fopen(tmp, "w");
	if (!f) {
		free(tmp);
		return -1;
	}
	if (fputs(text, f) == EOF) {
		fclose(f);
		unlink(tmp);
		free(tmp);
		return -1;
	}
	fclose(f);

	if (rename(tmp, path) != 0) {
		unlink(tmp);
		free(tmp);
		return -1;
	}
	free(tmp);
	return 0;
}

int
meta_read(const char *path, token_meta_t * meta)
{
	memset(meta, 0, sizeof(*meta));

	char *text = read_file(path);
	if (!text)
		return -1;

	gcry_sexp_t root;
	if (gcry_sexp_new(&root, text, 0, 1) != 0) {
		free(text);
		return -1;
	}
	free(text);

	meta->version = sexp_int(root, "version", 0);
	meta->serial_num = sexp_int(root, "serial", 0);
	meta->label = sexp_strdup(root, "label");
	meta->created_at = sexp_strdup(root, "created-at");
	meta->pin_max_retries = sexp_int(root, "pin-max-retries", 0);

	/* Read per-slot fields */
	for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
		char key[64];
		snprintf(key, sizeof(key), "slot-%d-algorithm", i);
		meta->algorithm[i] = sexp_strdup(root, key);
		snprintf(key, sizeof(key), "slot-%d-public-key-hex", i);
		meta->public_key_hex[i] = sexp_strdup(root, key);
		snprintf(key, sizeof(key), "slot-%d-key-fpr", i);
		meta->key_fpr_hex[i] = sexp_strdup(root, key);
		snprintf(key, sizeof(key), "slot-%d-key-time", i);
		meta->key_time[i] = sexp_strdup(root, key);
		snprintf(key, sizeof(key), "slot-%d-allowed-mechs", i);
		meta->allowed_mechs[i] = sexp_strdup(root, key);
	}

	gcry_sexp_release(root);
	return 0;
}

int
meta_write(const char *path, const token_meta_t * meta)
{
	gcry_sexp_t root;
	gcry_error_t err;

	/*
	 * Build the S-expression with per-slot fields.
	 * Empty slots are written as empty strings.
	 */
	err = gcry_sexp_build(&root, NULL,
			      "(meta"
			      " (version %d)"
			      " (serial %d)"
			      " (label %s)"
			      " (slot-0-algorithm %s)"
			      " (slot-0-public-key-hex %s)"
			      " (slot-0-key-fpr %s)"
			      " (slot-0-key-time %s)"
			      " (slot-0-allowed-mechs %s)"
			      " (slot-1-algorithm %s)"
			      " (slot-1-public-key-hex %s)"
			      " (slot-1-key-fpr %s)"
			      " (slot-1-key-time %s)"
			      " (slot-1-allowed-mechs %s)"
			      " (slot-2-algorithm %s)"
			      " (slot-2-public-key-hex %s)"
			      " (slot-2-key-fpr %s)"
			      " (slot-2-key-time %s)"
			      " (slot-2-allowed-mechs %s)"
			      " (created-at %s)"
			      " (pin-max-retries %d))",
			      meta->version,
			      meta->serial_num,
			      meta->label ? meta->label : "",
			      meta->algorithm[0] ? meta->algorithm[0] : "",
			      meta->public_key_hex[0] ? meta->
			      public_key_hex[0] : "",
			      meta->key_fpr_hex[0] ? meta->key_fpr_hex[0] : "",
			      meta->key_time[0] ? meta->key_time[0] : "",
			      meta->allowed_mechs[0] ? meta->
			      allowed_mechs[0] : "",
			      meta->algorithm[1] ? meta->algorithm[1] : "",
			      meta->public_key_hex[1] ? meta->
			      public_key_hex[1] : "",
			      meta->key_fpr_hex[1] ? meta->key_fpr_hex[1] : "",
			      meta->key_time[1] ? meta->key_time[1] : "",
			      meta->allowed_mechs[1] ? meta->
			      allowed_mechs[1] : "",
			      meta->algorithm[2] ? meta->algorithm[2] : "",
			      meta->public_key_hex[2] ? meta->
			      public_key_hex[2] : "",
			      meta->key_fpr_hex[2] ? meta->key_fpr_hex[2] : "",
			      meta->key_time[2] ? meta->key_time[2] : "",
			      meta->allowed_mechs[2] ? meta->
			      allowed_mechs[2] : "",
			      meta->created_at ? meta->created_at : "",
			      meta->pin_max_retries);
	if (err)
		return -1;

	/* Use advanced format for human-readable output */
	size_t len = gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	if (!len) {
		gcry_sexp_release(root);
		return -1;
	}

	char *text = malloc(len);
	if (!text) {
		gcry_sexp_release(root);
		return -1;
	}

	gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, text, len);
	gcry_sexp_release(root);

	int rc = atomic_write(path, text);
	free(text);
	return rc;
}

void
meta_free(token_meta_t * meta)
{
	free(meta->label);
	for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
		free(meta->algorithm[i]);
		free(meta->public_key_hex[i]);
		free(meta->key_fpr_hex[i]);
		free(meta->key_time[i]);
		free(meta->allowed_mechs[i]);
	}
	free(meta->created_at);
	memset(meta, 0, sizeof(*meta));
}

int
state_read(const char *token_dir, token_state_t * state)
{
	state->pin_retries = -1;
	state->disconnected = 0;

	char path[768];
	snprintf(path, sizeof(path), "%s/state", token_dir);

	char *text = read_file(path);
	if (!text)
		return -1;

	gcry_sexp_t root;
	if (gcry_sexp_new(&root, text, 0, 1) != 0) {
		free(text);
		return -1;
	}
	free(text);

	state->pin_retries = sexp_int(root, "pin-retries", -1);
	state->disconnected = sexp_int(root, "disconnected", 0);
	gcry_sexp_release(root);
	return 0;
}

int
state_write(const char *token_dir, const token_state_t * state)
{
	gcry_sexp_t root;
	gcry_error_t err = gcry_sexp_build(&root, NULL,
					    "(state"
					    " (pin-retries %d)"
					    " (disconnected %d))",
					    state->pin_retries,
					    state->disconnected);
	if (err)
		return -1;

	size_t len = gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	if (!len) {
		gcry_sexp_release(root);
		return -1;
	}

	char *text = malloc(len);
	if (!text) {
		gcry_sexp_release(root);
		return -1;
	}

	gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, text, len);
	gcry_sexp_release(root);

	char path[768];
	snprintf(path, sizeof(path), "%s/state", token_dir);

	int rc = atomic_write(path, text);
	free(text);
	return rc;
}
