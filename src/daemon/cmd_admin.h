/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CMD_ADMIN_H
# define RELIQUARY_CMD_ADMIN_H
# include <assuan.h>
gpg_error_t cmd_store_status(assuan_context_t ctx, char *line);
gpg_error_t cmd_init_store(assuan_context_t ctx, char *line);
gpg_error_t cmd_create_token(assuan_context_t ctx, char *line);
gpg_error_t cmd_genkey(assuan_context_t ctx, char *line);
gpg_error_t store_key_into_slot(const char *store_path, const char *label,
				int slot, const unsigned char *keydata,
				size_t keydata_len, const unsigned char *mk,
				const char *additions, char algo_out[64]);
gpg_error_t cmd_import_slot(assuan_context_t ctx, char *line);
gpg_error_t cmd_delete_token(assuan_context_t ctx, char *line);
gpg_error_t cmd_clear_token(assuan_context_t ctx, char *line);
gpg_error_t cmd_unblock_token(assuan_context_t ctx, char *line);
gpg_error_t cmd_change_pin(assuan_context_t ctx, char *line);
gpg_error_t cmd_disconnect_token(assuan_context_t ctx, char *line);
gpg_error_t cmd_connect_token(assuan_context_t ctx, char *line);
#endif
