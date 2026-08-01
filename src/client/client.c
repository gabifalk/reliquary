/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Resolve the daemon socket path into buf. Returns the path (buf, or the
 * RELIQUARY_SOCKET override), or NULL if it can't be determined.
 */
static const char *
resolve_socket_path(char *buf, size_t buflen)
{
	const char *override = getenv("RELIQUARY_SOCKET");
	if (override)
		return override;

	const char *xdg = getenv("XDG_RUNTIME_DIR");
	if (!xdg) {
		fprintf(stderr, "Error: $XDG_RUNTIME_DIR is not set\n");
		return NULL;
	}
	snprintf(buf, buflen, "%s/reliquary/socket", xdg);
	return buf;
}

int
client_connect(assuan_context_t * ctx)
{
	char path_buf[512];
	const char *socket_path =
	    resolve_socket_path(path_buf, sizeof(path_buf));
	if (!socket_path)
		return -1;

	gpg_error_t err = assuan_new(ctx);
	if (err) {
		fprintf(stderr, "Error: assuan_new: %s\n", gpg_strerror(err));
		return -1;
	}

	err = assuan_socket_connect(*ctx, socket_path, 0, 0);
	if (err) {
		fprintf(stderr, "Error: cannot connect to %s: %s\n",
			socket_path, gpg_strerror(err));
		assuan_release(*ctx);
		return -1;
	}

	return 0;
}

struct collect_buf {
	char *data;
	size_t len;
	size_t cap;
};

static gpg_error_t
data_cb(void *opaque, const void *data, size_t len)
{
	struct collect_buf *cb = opaque;
	if (cb->len + len > cb->cap) {
		cb->cap = (cb->len + len) * 2 + 64;
		cb->data = realloc(cb->data, cb->cap);
		if (!cb->data)
			return gpg_error(GPG_ERR_ENOMEM);
	}
	memcpy(cb->data + cb->len, data, len);
	cb->len += len;
	return 0;
}

gpg_error_t
client_command(assuan_context_t ctx, const char *cmd,
	       char **data_out, size_t * data_len)
{
	struct collect_buf cb = { NULL, 0, 0 };
	gpg_error_t err =
	    assuan_transact(ctx, cmd, data_cb, &cb, NULL, NULL, NULL, NULL);
	if (data_out) {
		*data_out = cb.data;
		*data_len = cb.len;
	} else {
		free(cb.data);
	}
	return err;
}

gpg_error_t
client_command_ok(assuan_context_t ctx, const char *cmd)
{
	return client_command(ctx, cmd, NULL, NULL);
}

struct inquire_data {
	assuan_context_t ctx;
	const unsigned char *data;
	size_t len;
};

static gpg_error_t
inquire_send_cb(void *opaque, const char *name)
{
	struct inquire_data *d = opaque;
	(void)name;		/* one inquire per import; keyword unused */
	return assuan_send_data(d->ctx, d->data, d->len);
}

gpg_error_t
client_command_with_data(assuan_context_t ctx, const char *cmd,
			 const unsigned char *data, size_t data_len)
{
	struct inquire_data d = { ctx, data, data_len };
	return assuan_transact(ctx, cmd, NULL, NULL,
			       inquire_send_cb, &d, NULL, NULL);
}

/*
 * Like client_command_with_data, but also collects the server's D-line
 * reply (e.g. DECRYPT: ciphertext streamed in via INQUIRE, plaintext
 * streamed back as the data reply). Caller frees the reply in out.
 */
gpg_error_t
client_command_data_reply(assuan_context_t ctx, const char *cmd,
			  const unsigned char *in, size_t in_len,
			  unsigned char **out, size_t *out_len)
{
	struct inquire_data d = { ctx, in, in_len };
	struct collect_buf cb = { NULL, 0, 0 };
	gpg_error_t err = assuan_transact(ctx, cmd, data_cb, &cb,
					  inquire_send_cb, &d, NULL, NULL);
	if (err) {
		free(cb.data);
		return err;
	}
	*out = (unsigned char *)cb.data;
	*out_len = cb.len;
	return 0;
}

gpg_error_t
client_command_status(assuan_context_t ctx, const char *cmd,
		      gpg_error_t (*status_cb)(void *, const char *),
		      void *cb_arg)
{
	return assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL,
			       status_cb, cb_arg);
}

void
client_disconnect(assuan_context_t ctx)
{
	assuan_release(ctx);
}
