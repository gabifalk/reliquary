/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "server.h"
#include "cmd_session.h"
#include "cmd_admin.h"
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
	assuan_register_command(ctx, "OPEN_SESSION", cmd_open_session, NULL);
	assuan_register_command(ctx, "CLOSE_SESSION", cmd_close_session, NULL);
	assuan_register_command(ctx, "LOGIN", cmd_login, NULL);
	assuan_register_command(ctx, "LOGOUT", cmd_logout, NULL);
	assuan_register_command(ctx, "LIST_TOKENS", cmd_list_tokens, NULL);
	assuan_register_command(ctx, "GET_MECHANISM_LIST",
				cmd_get_mechanism_list, NULL);
	assuan_register_command(ctx, "LIST_KEYS", cmd_list_keys, NULL);
	assuan_register_command(ctx, "GET_ATTRIBUTE", cmd_get_attribute, NULL);
	assuan_register_command(ctx, "SET_ATTRIBUTE", cmd_set_attribute, NULL);
	assuan_register_command(ctx, "STORE_STATUS", cmd_store_status, NULL);
	assuan_register_command(ctx, "INIT_STORE", cmd_init_store, NULL);
	assuan_register_command(ctx, "CREATE_TOKEN", cmd_create_token, NULL);
	assuan_register_command(ctx, "GENKEY", cmd_genkey, NULL);
	assuan_register_command(ctx, "IMPORT_SLOT", cmd_import_slot, NULL);
	assuan_register_command(ctx, "DELETE_TOKEN", cmd_delete_token, NULL);
	assuan_register_command(ctx, "CLEAR_TOKEN", cmd_clear_token, NULL);
	assuan_register_command(ctx, "DISCONNECT_TOKEN",
				cmd_disconnect_token, NULL);
	assuan_register_command(ctx, "CONNECT_TOKEN",
				cmd_connect_token, NULL);
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
