/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_SERVER_H
# define RELIQUARY_SERVER_H

# include "session.h"
# include <assuan.h>

int server_init(assuan_context_t * ctx, int fd, session_t * sess);
int server_run(assuan_context_t ctx);

#endif
