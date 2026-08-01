/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "server.h"
#include <string.h>

static gpg_error_t
cmd_nop(assuan_context_t ctx, char *line)
{
	(void)ctx;
	(void)line;
	return 0;
}

static void
register_commands(assuan_context_t ctx)
{
	assuan_register_command(ctx, "NOP", cmd_nop, NULL);
}

int
server_init(assuan_context_t * ctx, int fd, session_t * sess)
{
	gpg_error_t err;
	err = assuan_new(ctx);
	if (err)
		return -1;
	err =
	    assuan_init_socket_server(*ctx, fd, ASSUAN_SOCKET_SERVER_ACCEPTED);
	if (err) {
		assuan_release(*ctx);
		return -1;
	}
	assuan_set_hello_line(*ctx, "Reliquary daemon ready");
	assuan_set_pointer(*ctx, sess);
	register_commands(*ctx);
	return 0;
}

int
server_run(assuan_context_t ctx)
{
	gpg_error_t err;
	for (;;) {
		err = assuan_accept(ctx);
		if (gpg_err_code(err) == GPG_ERR_EOF
		    || err == (gpg_error_t) (-1))
			break;
		if (err)
			break;
		err = assuan_process(ctx);
		if (err)
			continue;
	}
	return 0;
}
