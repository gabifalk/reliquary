/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TESTHELPER_H
# define TESTHELPER_H

# include <assuan.h>
# include <sys/socket.h>
# include <sys/wait.h>
# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <string.h>

# include "server.h"
# include "session.h"
# include "crypto.h"

static inline int
test_server_start(const char *store_path,
		  assuan_context_t * client_ctx, pid_t * child_pid)
{
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
		return -1;

	pid_t pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}

	if (pid == 0) {
		close(fds[1]);
		crypto_init();
		session_t sess;
		session_init(&sess, getuid(), store_path);
		assuan_context_t srv_ctx;
		if (server_init(&srv_ctx, fds[0], &sess) != 0)
			_exit(1);
		server_run(srv_ctx);
		assuan_release(srv_ctx);
		session_destroy(&sess);
		_exit(0);
	}

	close(fds[0]);
	*child_pid = pid;

	gpg_error_t err = assuan_new(client_ctx);
	if (err) {
		close(fds[1]);
		return -1;
	}

	err = assuan_socket_connect_fd(*client_ctx, fds[1], 0);
	if (err) {
		assuan_release(*client_ctx);
		close(fds[1]);
		return -1;
	}
	return 0;
}

static inline void
test_server_stop(assuan_context_t client_ctx, pid_t child_pid)
{
	assuan_release(client_ctx);
	waitpid(child_pid, NULL, 0);
}

struct _collect_data {
	char *buf;
	size_t len;
	size_t cap;
};

static gpg_error_t
_data_cb(void *opaque, const void *data, size_t datalen)
{
	struct _collect_data *cd = opaque;
	if (cd->len + datalen > cd->cap) {
		cd->cap = (cd->len + datalen) * 2 + 64;
		cd->buf = realloc(cd->buf, cd->cap);
	}
	memcpy(cd->buf + cd->len, data, datalen);
	cd->len += datalen;
	return 0;
}

static inline gpg_error_t
test_command(assuan_context_t ctx, const char *cmd,
	     char **data_out, size_t * data_len)
{
	struct _collect_data cd = { NULL, 0, 0 };
	gpg_error_t err =
	    assuan_transact(ctx, cmd, _data_cb, &cd, NULL, NULL, NULL, NULL);
	if (data_out) {
		*data_out = cd.buf;
		*data_len = cd.len;
	} else {
		free(cd.buf);
	}
	return err;
}

static inline gpg_error_t
test_command_ok(assuan_context_t ctx, const char *cmd)
{
	return test_command(ctx, cmd, NULL, NULL);
}

struct _collect_status {
	char *buf;
	size_t len;
	size_t cap;
};

static gpg_error_t
_status_cb(void *opaque, const char *line)
{
	struct _collect_status *cs = opaque;
	size_t l = strlen(line);
	if (cs->len + l + 2 > cs->cap) {
		cs->cap = (cs->len + l + 2) * 2 + 64;
		cs->buf = realloc(cs->buf, cs->cap);
	}
	memcpy(cs->buf + cs->len, line, l);
	cs->len += l;
	cs->buf[cs->len++] = '\n';
	cs->buf[cs->len] = '\0';
	return 0;
}

/* Collect all status-line payloads (without the leading "S ") into one
   newline-joined, null-terminated string. Caller frees *out. */
static inline gpg_error_t
test_command_status(assuan_context_t ctx, const char *cmd, char **out)
{
	struct _collect_status cs;
	cs.cap = 128;
	cs.len = 0;
	cs.buf = malloc(cs.cap);
	cs.buf[0] = '\0';
	gpg_error_t err = assuan_transact(ctx, cmd, NULL, NULL, NULL,
					  NULL, _status_cb, &cs);
	*out = cs.buf;
	return err;
}

#endif
