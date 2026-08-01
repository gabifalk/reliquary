/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_META_H
# define RELIQUARY_META_H

# include <stddef.h>
# include <string.h>

# define RELIQUARY_NUM_SLOTS 3
# define RELIQUARY_SLOT_SIGN    0
# define RELIQUARY_SLOT_ENCRYPT 1
# define RELIQUARY_SLOT_AUTH    2

/*
 * On-disk metadata format version.  Version 1 is the first release-quality
 * format and the baseline for any future migration.
 */
# define META_VERSION 1

typedef struct {
	int version;
	int serial_num;
	char *label;
	char *created_at;
	int pin_max_retries;
	/* Per-slot data (NULL = empty slot) */
	char *algorithm[RELIQUARY_NUM_SLOTS];
	char *public_key_hex[RELIQUARY_NUM_SLOTS];
	char *key_fpr_hex[RELIQUARY_NUM_SLOTS];	  /* OpenPGP fingerprint, hex */
	char *key_time[RELIQUARY_NUM_SLOTS];	  /* creation timestamp string */
	char *allowed_mechs[RELIQUARY_NUM_SLOTS];	  /* comma-separated mechanism-token list, or NULL */
} token_meta_t;

/* Algorithm type helpers */
static inline int
algo_is_rsa(const char *algo)
{
	return algo && strncmp(algo, "rsa", 3) == 0;
}

static inline int
algo_is_ed25519(const char *algo)
{
	return algo && strncmp(algo, "ed25519", 7) == 0;
}

static inline int
algo_is_ec(const char *algo)
{
	return algo && (strncmp(algo, "nistp", 5) == 0 || algo_is_ed25519(algo));
}

typedef struct {
	int pin_retries;	/* -1 = not present / use fallback */
	int disconnected;	/* 0 or 1 */
} token_state_t;

int meta_read(const char *path, token_meta_t * meta);
int meta_write(const char *path, const token_meta_t * meta);
void meta_free(token_meta_t * meta);

int state_read(const char *token_dir, token_state_t * state);
int state_write(const char *token_dir, const token_state_t * state);

#endif
