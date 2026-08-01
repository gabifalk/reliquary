/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_TOKENSTORE_H
# define RELIQUARY_TOKENSTORE_H

# include <stddef.h>

/* Longest permitted token label, in bytes. */
# define TOKENSTORE_MAX_LABEL 64

/*
 * Returns 1 if label is safe to use as a token directory name (non-empty,
 * within length, drawn from [A-Za-z0-9._-], and not "." or ".."), else 0.
 * Guards against path traversal / store escape via caller-supplied labels.
 */
int tokenstore_valid_label(const char *label);

void tokenstore_token_path(const char *store_path, const char *label,
			   char *out, size_t out_len);
int tokenstore_exists(const char *store_path, const char *label);
int tokenstore_create(const char *store_path, const char *label);
int tokenstore_remove(const char *store_path, const char *label);
int tokenstore_list(const char *store_path, char labels[][256], int max_labels);
int tokenstore_list_all(const char *store_path, char labels[][256], int max_labels);

#endif
