/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_SSHKEY_H
# define RELIQUARY_SSHKEY_H

# include <stddef.h>

/*
 * Return 1 if the OpenSSH key file at path is passphrase-protected, 0 if it
 * is an unencrypted OpenSSH key, -1 on error or unsupported format.
 */
int sshkey_is_encrypted(const char *path);

/*
 * Load an OpenSSH-format private key and convert it to a gcrypt canonical
 * private-key S-expression.
 *
 * If the key is encrypted, passphrase must be non-NULL (it is used to derive
 * the decryption key); for unencrypted keys passphrase is ignored and may be
 * NULL.
 *
 * On success (*sexp) receives malloc'd canonical S-expression bytes,
 * (*sexp_len) its length, and (*algo) a malloc'd algorithm name
 * ("ed25519", "rsa2048", "nistp256", ...). Caller frees (*sexp) and (*algo).
 *
 * Returns 0 on success, -1 on failure.
 */
int sshkey_load(const char *path, const char *passphrase,
		unsigned char **sexp, size_t *sexp_len, char **algo);

#endif
