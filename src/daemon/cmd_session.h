/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CMD_SESSION_H
# define RELIQUARY_CMD_SESSION_H
# include <assuan.h>
# include "session.h"

/*
 * Ensure the session is logged in, prompting for the PIN via a NEEDPIN
 * inquiry if needed.  No-op if sess->logged_in is already set.  Shared by
 * the neutral SIGN/DECRYPT/DERIVE handlers in this file and IMPORT_SLOT in
 * cmd_admin.c, so a caller that skips the explicit LOGIN (e.g. the
 * scd-proxy) still gets a PIN prompt on demand.
 *
 * CAUTION: this may perform an assuan_inquire(), which reuses libassuan's
 * inbound line buffer.  Any value the caller has parsed out of `line`
 * (other than data already copied into caller-owned storage) must not be
 * read again after this returns.
 */
gpg_error_t ensure_logged_in(assuan_context_t ctx, session_t * sess);

gpg_error_t cmd_open_session(assuan_context_t ctx, char *line);
gpg_error_t cmd_close_session(assuan_context_t ctx, char *line);
gpg_error_t cmd_login(assuan_context_t ctx, char *line);
gpg_error_t cmd_logout(assuan_context_t ctx, char *line);
gpg_error_t cmd_sign(assuan_context_t ctx, char *line);
gpg_error_t cmd_decrypt(assuan_context_t ctx, char *line);
gpg_error_t cmd_derive(assuan_context_t ctx, char *line);
gpg_error_t cmd_list_tokens(assuan_context_t ctx, char *line);
gpg_error_t cmd_get_mechanism_list(assuan_context_t ctx, char *line);
gpg_error_t cmd_list_keys(assuan_context_t ctx, char *line);
gpg_error_t cmd_get_attribute(assuan_context_t ctx, char *line);
gpg_error_t cmd_set_attribute(assuan_context_t ctx, char *line);
#endif
