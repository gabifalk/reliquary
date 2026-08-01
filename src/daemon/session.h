/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_SESSION_H
# define RELIQUARY_SESSION_H

# include <stddef.h>
# include <sys/types.h>
# include "meta.h"		/* for RELIQUARY_NUM_SLOTS */

typedef struct {
	uid_t uid;
	char store_path[512];
	char token_label[256];
	char token_dir[512];
	/* Per-slot state */
	char algorithm[RELIQUARY_NUM_SLOTS][64];
	unsigned char *key[RELIQUARY_NUM_SLOTS];
	size_t key_len[RELIQUARY_NUM_SLOTS];
	int logged_in;
	unsigned char *mk;	/* KEYWRAP_MK_LEN bytes in secure memory, or NULL */
} session_t;

void session_init(session_t * sess, uid_t uid, const char *store_path);
int session_open(session_t * sess, const char *label);
int session_login(session_t * sess, const char *pin, size_t pin_len);
void session_logout(session_t * sess);
void session_close(session_t * sess);
void session_destroy(session_t * sess);

#endif
