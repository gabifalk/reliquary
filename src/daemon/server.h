/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_SERVER_H
# define RELIQUARY_SERVER_H

# include <assuan.h>

int server_init(assuan_context_t * ctx, int fd);
int server_run(assuan_context_t ctx);

#endif
