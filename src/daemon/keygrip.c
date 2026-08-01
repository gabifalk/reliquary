/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "keygrip.h"
#include "hex.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int
compute_keygrip(const char *pubkey_hex, char *grip_out, size_t grip_size)
{
	if (!pubkey_hex || grip_size < 41)
		return -1;

	size_t hex_len = strlen(pubkey_hex);
	unsigned char *raw = malloc(hex_len / 2 + 1);
	size_t raw_len;
	if (!raw || hex_decode(pubkey_hex, raw, hex_len / 2 + 1, &raw_len) != 0) {
		free(raw);
		return -1;
	}

	gcry_sexp_t sexp;
	if (gcry_sexp_new(&sexp, raw, raw_len, 0) != 0) {
		free(raw);
		return -1;
	}
	free(raw);

	unsigned char grip[20];
	if (!gcry_pk_get_keygrip(sexp, grip)) {
		gcry_sexp_release(sexp);
		return -1;
	}
	gcry_sexp_release(sexp);

	char *hex = hex_encode(grip, 20);
	if (!hex)
		return -1;
	for (size_t i = 0; hex[i]; i++)
		if (hex[i] >= 'a' && hex[i] <= 'f')
			hex[i] -= 32;
	strncpy(grip_out, hex, grip_size - 1);
	grip_out[grip_size - 1] = '\0';
	free(hex);
	return 0;
}

int
keygrip_computable(const unsigned char *pubkey_canon, size_t len)
{
	/*
	 * gcry_pk_get_keygrip() calls log_fatal()->abort() on some malformed
	 * public keys. Compute in a child so the abort is contained: a child
	 * killed by a signal, or exiting nonzero, means "not computable".
	 * The child touches only the public key and _exit()s, so the session
	 * master key it inherits copy-on-write is never used or dumped (setgid
	 * keeps the process non-dumpable).
	 */
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		gcry_sexp_t s;
		unsigned char grip[20];
		if (gcry_sexp_new(&s, pubkey_canon, len, 0) != 0)
			_exit(1);
		if (!gcry_pk_get_keygrip(s, grip))	/* may abort() */
			_exit(1);
		_exit(0);
	}
	int st;
	if (waitpid(pid, &st, 0) < 0)
		return -1;
	return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}
