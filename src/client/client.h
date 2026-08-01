/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CLIENT_H
# define RELIQUARY_CLIENT_H

# include <assuan.h>

int client_connect(assuan_context_t * ctx);
gpg_error_t client_command(assuan_context_t ctx, const char *cmd,
			   char **data_out, size_t * data_len);
gpg_error_t client_command_ok(assuan_context_t ctx, const char *cmd);
gpg_error_t client_command_with_data(assuan_context_t ctx, const char *cmd,
				     const unsigned char *data, size_t data_len);
gpg_error_t client_command_data_reply(assuan_context_t ctx, const char *cmd,
				      const unsigned char *in, size_t in_len,
				      unsigned char **out, size_t *out_len);
gpg_error_t client_command_status(assuan_context_t ctx, const char *cmd,
				  gpg_error_t (*status_cb)(void *,
							   const char *),
				  void *cb_arg);
void client_disconnect(assuan_context_t ctx);

#endif
