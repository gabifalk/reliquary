/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto_rsa.h"
#include "secmem.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>

/*
 * Serialize a gcry_sexp_t to a canonical buffer.  When secure is nonzero the
 * buffer is drawn from locked, non-swappable secure memory (for private-key
 * material) and must be freed via secure_free; otherwise it is a plain malloc
 * buffer freed via free (for public keys).
 */
static int
sexp_to_buf(gcry_sexp_t sexp, unsigned char **out, size_t * out_len, int secure)
{
	size_t len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
	if (len == 0)
		return -1;

	unsigned char *buf = secure ? secure_alloc(len) : malloc(len);
	if (!buf)
		return -1;

	size_t written = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, buf, len);
	if (written == 0) {
		if (secure)
			secure_free(buf, len);
		else
			free(buf);
		return -1;
	}

	*out = buf;
	*out_len = written;
	return 0;
}

/*
 * Extract raw data bytes from a named sub-node of parent sexp.
 * parent must contain a token node whose first data element is the value.
 */
static int
extract_mpi_data(gcry_sexp_t parent, const char *token,
		 unsigned char **out, size_t * out_len)
{
	gcry_sexp_t node = gcry_sexp_find_token(parent, token, 0);
	if (!node)
		return -1;

	size_t len = 0;
	const char *data = gcry_sexp_nth_data(node, 1, &len);
	if (!data || len == 0) {
		gcry_sexp_release(node);
		return -1;
	}

	unsigned char *buf = malloc(len);
	if (!buf) {
		gcry_sexp_release(node);
		return -1;
	}

	memcpy(buf, data, len);
	gcry_sexp_release(node);

	*out = buf;
	*out_len = len;
	return 0;
}

int
crypto_rsa_keygen(unsigned int nbits, unsigned char **key, size_t * key_len)
{
	gcry_sexp_t params = NULL;
	gcry_sexp_t keypair = NULL;
	gcry_error_t err;
	int rc = -1;

	err =
	    gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits %u)))", nbits);
	if (err)
		goto out;

	err = gcry_pk_genkey(&keypair, params);
	if (err)
		goto out;

	/* The keypair carries the private key -- serialize into secure memory. */
	rc = sexp_to_buf(keypair, key, key_len, 1);

 out:
	if (params)
		gcry_sexp_release(params);
	if (keypair)
		gcry_sexp_release(keypair);
	return rc;
}

int
crypto_rsa_extract_pubkey(const unsigned char *key, size_t key_len,
			  unsigned char **pubkey, size_t * pubkey_len)
{
	gcry_sexp_t keypair = NULL;
	gcry_sexp_t pub = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&keypair, key, key_len, 0);
	if (err)
		goto out;

	/* Try public-key first (from gcry_pk_genkey output) */
	pub = gcry_sexp_find_token(keypair, "public-key", 0);
	if (!pub) {
		/*
		 * private-key only (from GnuPG keytocard): build public-key
		 * from n and e components
		 */
		gcry_sexp_t priv =
		    gcry_sexp_find_token(keypair, "private-key", 0);
		if (!priv)
			goto out;
		gcry_sexp_t rsa = gcry_sexp_find_token(priv, "rsa", 0);
		gcry_sexp_release(priv);
		if (!rsa)
			goto out;
		gcry_mpi_t n = NULL, e = NULL;
		gcry_sexp_t n_node = gcry_sexp_find_token(rsa, "n", 0);
		gcry_sexp_t e_node = gcry_sexp_find_token(rsa, "e", 0);
		if (n_node)
			n = gcry_sexp_nth_mpi(n_node, 1, GCRYMPI_FMT_USG);
		if (e_node)
			e = gcry_sexp_nth_mpi(e_node, 1, GCRYMPI_FMT_USG);
		gcry_sexp_release(n_node);
		gcry_sexp_release(e_node);
		gcry_sexp_release(rsa);
		if (n && e)
			err = gcry_sexp_build(&pub, NULL,
					      "(public-key(rsa(n%m)(e%m)))",
					      n, e);
		gcry_mpi_release(n);
		gcry_mpi_release(e);
		if (err || !pub)
			goto out;
	}

	/* Public key only -- plain heap is fine. */
	rc = sexp_to_buf(pub, pubkey, pubkey_len, 0);

 out:
	if (keypair)
		gcry_sexp_release(keypair);
	if (pub)
		gcry_sexp_release(pub);
	return rc;
}

/*
 * Get RSA key size in bytes from a keypair S-expression.
 */
static size_t
rsa_key_bytes(gcry_sexp_t key_sexp)
{
	/* Try direct, then inside public-key / private-key */
	gcry_sexp_t rsa = gcry_sexp_find_token(key_sexp, "rsa", 0);
	if (!rsa) {
		gcry_sexp_t sub =
		    gcry_sexp_find_token(key_sexp, "public-key", 0);
		if (!sub)
			sub = gcry_sexp_find_token(key_sexp, "private-key", 0);
		if (sub) {
			rsa = gcry_sexp_find_token(sub, "rsa", 0);
			gcry_sexp_release(sub);
		}
	}
	if (!rsa)
		return 0;
	gcry_sexp_t n_node = gcry_sexp_find_token(rsa, "n", 0);
	gcry_sexp_release(rsa);
	if (!n_node)
		return 0;
	gcry_mpi_t n = gcry_sexp_nth_mpi(n_node, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(n_node);
	if (!n)
		return 0;
	size_t nbits = gcry_mpi_get_nbits(n);
	gcry_mpi_release(n);
	return (nbits + 7) / 8;
}

int
crypto_rsa_sign_raw(const unsigned char *key, size_t key_len,
		    const unsigned char *data, size_t data_len,
		    unsigned char **sig, size_t * sig_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t data_sexp = NULL;
	gcry_sexp_t sig_sexp = NULL;
	gcry_sexp_t rsa_node = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&privkey, key, key_len, 0);
	if (err)
		goto out;

	/*
	 * Build PKCS#1 v1.5 type 1 padded block:
	 * 0x00 0x01 [0xFF padding] 0x00 [data]
	 */
	size_t k = rsa_key_bytes(privkey);
	if (k == 0 || data_len + 11 > k)
		goto out;

	unsigned char *padded = malloc(k);
	if (!padded)
		goto out;
	padded[0] = 0x00;
	padded[1] = 0x01;
	memset(padded + 2, 0xFF, k - data_len - 3);
	padded[k - data_len - 1] = 0x00;
	memcpy(padded + k - data_len, data, data_len);

	err = gcry_sexp_build(&data_sexp, NULL,
			      "(data (flags raw) (value %b))", (int)k, padded);
	free(padded);
	if (err)
		goto out;

	err = gcry_pk_sign(&sig_sexp, data_sexp, privkey);
	if (err)
		goto out;

	rsa_node = gcry_sexp_find_token(sig_sexp, "rsa", 0);
	if (!rsa_node)
		goto out;

	gcry_mpi_t s_mpi = NULL;
	gcry_sexp_t s_node = gcry_sexp_find_token(rsa_node, "s", 0);
	if (!s_node)
		goto out;
	s_mpi = gcry_sexp_nth_mpi(s_node, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(s_node);
	if (!s_mpi)
		goto out;

	size_t slen = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &slen, s_mpi);
	*sig = malloc(slen);
	if (!*sig) {
		gcry_mpi_release(s_mpi);
		goto out;
	}
	gcry_mpi_print(GCRYMPI_FMT_USG, *sig, slen, sig_len, s_mpi);
	gcry_mpi_release(s_mpi);
	rc = 0;

 out:
	if (rsa_node)
		gcry_sexp_release(rsa_node);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	if (data_sexp)
		gcry_sexp_release(data_sexp);
	if (privkey)
		gcry_sexp_release(privkey);
	return rc;
}

int
crypto_rsa_sign_pkcs1(const unsigned char *key, size_t key_len,
		      int hash_algo,
		      const unsigned char *hash, size_t hash_len,
		      unsigned char **sig, size_t * sig_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t sig_sexp = NULL;
	gcry_sexp_t rsa_node = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&privkey, key, key_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags pkcs1) (hash %s %b))",
			      gcry_md_algo_name(hash_algo),
			      (int)hash_len, hash);
	if (err)
		goto out;

	err = gcry_pk_sign(&sig_sexp, data, privkey);
	if (err)
		goto out;

	/* Extract "s" from sig-val -> rsa -> s */
	rsa_node = gcry_sexp_find_token(sig_sexp, "rsa", 0);
	if (!rsa_node)
		goto out;

	rc = extract_mpi_data(rsa_node, "s", sig, sig_len);

 out:
	if (privkey)
		gcry_sexp_release(privkey);
	if (data)
		gcry_sexp_release(data);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	if (rsa_node)
		gcry_sexp_release(rsa_node);
	return rc;
}

int
crypto_rsa_verify_pkcs1(const unsigned char *pubkey, size_t pubkey_len,
			int hash_algo,
			const unsigned char *hash, size_t hash_len,
			const unsigned char *sig, size_t sig_len)
{
	gcry_sexp_t pub = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t sig_sexp = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&pub, pubkey, pubkey_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags pkcs1) (hash %s %b))",
			      gcry_md_algo_name(hash_algo),
			      (int)hash_len, hash);
	if (err)
		goto out;

	err = gcry_sexp_build(&sig_sexp, NULL,
			      "(sig-val (rsa (s %b)))", (int)sig_len, sig);
	if (err)
		goto out;

	err = gcry_pk_verify(sig_sexp, data, pub);
	rc = err ? -1 : 0;

 out:
	if (pub)
		gcry_sexp_release(pub);
	if (data)
		gcry_sexp_release(data);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	return rc;
}

int
crypto_rsa_sign_pss(const unsigned char *key, size_t key_len,
		    int hash_algo,
		    const unsigned char *hash, size_t hash_len,
		    size_t salt_len, unsigned char **sig, size_t * sig_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t sig_sexp = NULL;
	gcry_sexp_t rsa_node = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&privkey, key, key_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags pss) (hash %s %b) (salt-length %u))",
			      gcry_md_algo_name(hash_algo),
			      (int)hash_len, hash, (unsigned int)salt_len);
	if (err)
		goto out;

	err = gcry_pk_sign(&sig_sexp, data, privkey);
	if (err)
		goto out;

	rsa_node = gcry_sexp_find_token(sig_sexp, "rsa", 0);
	if (!rsa_node)
		goto out;

	rc = extract_mpi_data(rsa_node, "s", sig, sig_len);

 out:
	if (privkey)
		gcry_sexp_release(privkey);
	if (data)
		gcry_sexp_release(data);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	if (rsa_node)
		gcry_sexp_release(rsa_node);
	return rc;
}

int
crypto_rsa_verify_pss(const unsigned char *pubkey, size_t pubkey_len,
		      int hash_algo,
		      const unsigned char *hash, size_t hash_len,
		      size_t salt_len, const unsigned char *sig, size_t sig_len)
{
	gcry_sexp_t pub = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t sig_sexp = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&pub, pubkey, pubkey_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags pss) (hash %s %b) (salt-length %u))",
			      gcry_md_algo_name(hash_algo),
			      (int)hash_len, hash, (unsigned int)salt_len);
	if (err)
		goto out;

	err = gcry_sexp_build(&sig_sexp, NULL,
			      "(sig-val (rsa (s %b)))", (int)sig_len, sig);
	if (err)
		goto out;

	err = gcry_pk_verify(sig_sexp, data, pub);
	rc = err ? -1 : 0;

 out:
	if (pub)
		gcry_sexp_release(pub);
	if (data)
		gcry_sexp_release(data);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	return rc;
}

int
crypto_rsa_encrypt_pkcs1(const unsigned char *pubkey, size_t pubkey_len,
			 const unsigned char *pt, size_t pt_len,
			 unsigned char **ct, size_t * ct_len)
{
	gcry_sexp_t pub = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t enc_sexp = NULL;
	gcry_sexp_t rsa_node = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&pub, pubkey, pubkey_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags pkcs1) (value %b))",
			      (int)pt_len, pt);
	if (err)
		goto out;

	err = gcry_pk_encrypt(&enc_sexp, data, pub);
	if (err)
		goto out;

	rsa_node = gcry_sexp_find_token(enc_sexp, "rsa", 0);
	if (!rsa_node)
		goto out;

	rc = extract_mpi_data(rsa_node, "a", ct, ct_len);

 out:
	if (pub)
		gcry_sexp_release(pub);
	if (data)
		gcry_sexp_release(data);
	if (enc_sexp)
		gcry_sexp_release(enc_sexp);
	if (rsa_node)
		gcry_sexp_release(rsa_node);
	return rc;
}

int
crypto_rsa_decrypt_pkcs1(const unsigned char *key, size_t key_len,
			 const unsigned char *ct, size_t ct_len,
			 unsigned char **pt, size_t * pt_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t enc_sexp = NULL;
	gcry_sexp_t plain_sexp = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&privkey, key, key_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&enc_sexp, NULL,
			      "(enc-val (flags pkcs1) (rsa (a %b)))",
			      (int)ct_len, ct);
	if (err)
		goto out;

	err = gcry_pk_decrypt(&plain_sexp, enc_sexp, privkey);
	if (err)
		goto out;

	{
		size_t len = 0;
		const char *data = gcry_sexp_nth_data(plain_sexp, 1, &len);
		if (!data || len == 0)
			goto out;

		/*
		 * Recovered plaintext (typically a message session key) is
		 * secret -- keep it in locked memory; free via secure_free.
		 */
		unsigned char *buf = secure_alloc(len);
		if (!buf)
			goto out;

		memcpy(buf, data, len);
		*pt = buf;
		*pt_len = len;
		rc = 0;
	}

 out:
	if (privkey)
		gcry_sexp_release(privkey);
	if (enc_sexp)
		gcry_sexp_release(enc_sexp);
	if (plain_sexp)
		gcry_sexp_release(plain_sexp);
	return rc;
}

int
crypto_rsa_encrypt_oaep(const unsigned char *pubkey, size_t pubkey_len,
			int hash_algo,
			const unsigned char *pt, size_t pt_len,
			unsigned char **ct, size_t * ct_len)
{
	gcry_sexp_t pub = NULL;
	gcry_sexp_t data = NULL;
	gcry_sexp_t enc_sexp = NULL;
	gcry_sexp_t rsa_node = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&pub, pubkey, pubkey_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&data, NULL,
			      "(data (flags oaep) (hash-algo %s) (value %b))",
			      gcry_md_algo_name(hash_algo), (int)pt_len, pt);
	if (err)
		goto out;

	err = gcry_pk_encrypt(&enc_sexp, data, pub);
	if (err)
		goto out;

	rsa_node = gcry_sexp_find_token(enc_sexp, "rsa", 0);
	if (!rsa_node)
		goto out;

	rc = extract_mpi_data(rsa_node, "a", ct, ct_len);

 out:
	if (pub)
		gcry_sexp_release(pub);
	if (data)
		gcry_sexp_release(data);
	if (enc_sexp)
		gcry_sexp_release(enc_sexp);
	if (rsa_node)
		gcry_sexp_release(rsa_node);
	return rc;
}

int
crypto_rsa_decrypt_oaep(const unsigned char *key, size_t key_len,
			int hash_algo,
			const unsigned char *ct, size_t ct_len,
			unsigned char **pt, size_t * pt_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t enc_sexp = NULL;
	gcry_sexp_t plain_sexp = NULL;
	gcry_error_t err;
	int rc = -1;

	err = gcry_sexp_new(&privkey, key, key_len, 0);
	if (err)
		goto out;

	err = gcry_sexp_build(&enc_sexp, NULL,
			      "(enc-val (flags oaep) (hash-algo %s) (rsa (a %b)))",
			      gcry_md_algo_name(hash_algo), (int)ct_len, ct);
	if (err)
		goto out;

	err = gcry_pk_decrypt(&plain_sexp, enc_sexp, privkey);
	if (err)
		goto out;

	{
		size_t len = 0;
		const char *data = gcry_sexp_nth_data(plain_sexp, 1, &len);
		if (!data || len == 0)
			goto out;

		/*
		 * Recovered plaintext (typically a message session key) is
		 * secret -- keep it in locked memory; free via secure_free.
		 */
		unsigned char *buf = secure_alloc(len);
		if (!buf)
			goto out;

		memcpy(buf, data, len);
		*pt = buf;
		*pt_len = len;
		rc = 0;
	}

 out:
	if (privkey)
		gcry_sexp_release(privkey);
	if (enc_sexp)
		gcry_sexp_release(enc_sexp);
	if (plain_sexp)
		gcry_sexp_release(plain_sexp);
	return rc;
}
