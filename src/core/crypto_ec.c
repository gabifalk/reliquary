/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto_ec.h"
#include "secmem.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>

/*
 * Generate an ECC keypair for the given curve name.
 * The full keypair S-expression is serialized in canonical format and
 * returned in *key / *key_len. It carries the private key, so it lives in
 * locked secure memory: caller must free via secure_free(*key, *key_len).
 */
int
crypto_ec_keygen(const char *curve, unsigned char **key, size_t * key_len)
{
	gcry_sexp_t params = NULL, keypair = NULL;
	gcry_error_t err;
	size_t slen;
	unsigned char *buf = NULL;

	/* EdDSA curves require the eddsa flag in the key */
	if (strcmp(curve, "Ed25519") == 0 || strcmp(curve, "Ed448") == 0) {
		err = gcry_sexp_build(&params, NULL,
				      "(genkey (ecc (curve %s) (flags eddsa)))",
				      curve);
	} else {
		err = gcry_sexp_build(&params, NULL,
				      "(genkey (ecc (curve %s)))", curve);
	}
	if (err)
		return -1;

	err = gcry_pk_genkey(&keypair, params);
	gcry_sexp_release(params);
	if (err)
		return -1;

	slen = gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, NULL, 0);
	if (!slen) {
		gcry_sexp_release(keypair);
		return -1;
	}

	buf = secure_alloc(slen);
	if (!buf) {
		gcry_sexp_release(keypair);
		return -1;
	}

	gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, buf, slen);
	gcry_sexp_release(keypair);

	*key = buf;
	*key_len = slen;
	return 0;
}

/* Extract the public-key S-expression from a full keypair blob. */
int
crypto_ec_extract_pubkey(const unsigned char *key, size_t key_len,
			 unsigned char **pubkey, size_t * pubkey_len)
{
	gcry_sexp_t keypair = NULL, pub = NULL;
	gcry_error_t err;
	size_t slen;
	unsigned char *buf = NULL;

	err = gcry_sexp_new(&keypair, key, key_len, 0);
	if (err)
		return -1;

	pub = gcry_sexp_find_token(keypair, "public-key", 0);
	if (!pub) {
		/*
		 * private-key only (SSH import / keytocard): build the
		 * public-key from the curve and q components.
		 */
		gcry_sexp_t priv =
		    gcry_sexp_find_token(keypair, "private-key", 0);
		if (!priv) {
			gcry_sexp_release(keypair);
			return -1;
		}
		gcry_sexp_t ecc = gcry_sexp_find_token(priv, "ecc", 0);
		gcry_sexp_release(priv);
		if (!ecc) {
			gcry_sexp_release(keypair);
			return -1;
		}
		gcry_sexp_t curve_node = gcry_sexp_find_token(ecc, "curve", 0);
		gcry_sexp_t q_node = gcry_sexp_find_token(ecc, "q", 0);
		gcry_sexp_release(ecc);

		size_t cnamelen = 0, qlen = 0;
		const char *cname = curve_node
		    ? gcry_sexp_nth_data(curve_node, 1, &cnamelen) : NULL;
		const char *qdata = q_node
		    ? gcry_sexp_nth_data(q_node, 1, &qlen) : NULL;

		if (cname && qdata && cnamelen < 64) {
			char cbuf[64];
			memcpy(cbuf, cname, cnamelen);
			cbuf[cnamelen] = '\0';
			int eddsa =
			    (cnamelen >= 7 && strncmp(cname, "Ed25519", 7) == 0)
			    || (cnamelen >= 5 && strncmp(cname, "Ed448", 5) == 0);
			if (eddsa)
				err = gcry_sexp_build(&pub, NULL,
				    "(public-key(ecc(curve %s)(flags eddsa)(q %b)))",
				    cbuf, (int)qlen, qdata);
			else
				err = gcry_sexp_build(&pub, NULL,
				    "(public-key(ecc(curve %s)(q %b)))",
				    cbuf, (int)qlen, qdata);
		}
		gcry_sexp_release(curve_node);
		gcry_sexp_release(q_node);
		gcry_sexp_release(keypair);
		if (err || !pub)
			return -1;
	} else {
		gcry_sexp_release(keypair);
	}

	slen = gcry_sexp_sprint(pub, GCRYSEXP_FMT_CANON, NULL, 0);
	if (!slen) {
		gcry_sexp_release(pub);
		return -1;
	}

	buf = malloc(slen);
	if (!buf) {
		gcry_sexp_release(pub);
		return -1;
	}

	gcry_sexp_sprint(pub, GCRYSEXP_FMT_CANON, buf, slen);
	gcry_sexp_release(pub);

	*pubkey = buf;
	*pubkey_len = slen;
	return 0;
}

/* Extract the private-key S-expression from a full keypair blob. */
static int
extract_privkey_sexp(const unsigned char *key, size_t key_len,
		     gcry_sexp_t * privkey_out)
{
	gcry_sexp_t keypair = NULL, priv = NULL;
	gcry_error_t err;

	err = gcry_sexp_new(&keypair, key, key_len, 0);
	if (err)
		return -1;

	/* Try "private-key" first, fall back to full keypair */
	priv = gcry_sexp_find_token(keypair, "private-key", 0);
	if (!priv) {
		/* Use keypair directly -- gcry_pk_sign can find the private key */
		*privkey_out = keypair;
		return 0;
	}
	gcry_sexp_release(keypair);
	*privkey_out = priv;
	return 0;
}

/* Detect whether an S-expression uses an EdDSA curve (Ed25519, Ed448). */
static int
is_eddsa_key(gcry_sexp_t key_sexp)
{
	gcry_sexp_t ecc = gcry_sexp_find_token(key_sexp, "ecc", 0);
	if (!ecc)
		return 0;

	gcry_sexp_t curve_node = gcry_sexp_find_token(ecc, "curve", 0);
	gcry_sexp_release(ecc);
	if (!curve_node)
		return 0;

	size_t clen = 0;
	const char *cname = gcry_sexp_nth_data(curve_node, 1, &clen);
	int eddsa = 0;
	if (cname) {
		eddsa = (clen >= 7 && strncmp(cname, "Ed25519", 7) == 0) ||
		    (clen >= 5 && strncmp(cname, "Ed448", 5) == 0);
	}
	gcry_sexp_release(curve_node);
	return eddsa;
}

/* ECDSA/EdDSA sign. Serialises the entire sig-val S-expression as the signature. */
int
crypto_ecdsa_sign(const unsigned char *key, size_t key_len,
		  const unsigned char *hash, size_t hash_len,
		  unsigned char **sig, size_t * sig_len)
{
	gcry_sexp_t privkey = NULL, data_sexp = NULL, sig_sexp = NULL;
	gcry_error_t err;
	size_t slen;
	unsigned char *buf = NULL;

	if (extract_privkey_sexp(key, key_len, &privkey) != 0)
		return -1;

	if (is_eddsa_key(privkey)) {
		err = gcry_sexp_build(&data_sexp, NULL,
				      "(data (flags eddsa) (hash-algo sha512) (value %b))",
				      (int)hash_len, hash);
	} else {
		err = gcry_sexp_build(&data_sexp, NULL,
				      "(data (flags raw) (value %b))",
				      (int)hash_len, hash);
	}
	if (err) {
		gcry_sexp_release(privkey);
		return -1;
	}

	err = gcry_pk_sign(&sig_sexp, data_sexp, privkey);
	gcry_sexp_release(data_sexp);
	gcry_sexp_release(privkey);
	if (err)
		return -1;

	slen = gcry_sexp_sprint(sig_sexp, GCRYSEXP_FMT_CANON, NULL, 0);
	if (!slen) {
		gcry_sexp_release(sig_sexp);
		return -1;
	}

	buf = malloc(slen);
	if (!buf) {
		gcry_sexp_release(sig_sexp);
		return -1;
	}

	gcry_sexp_sprint(sig_sexp, GCRYSEXP_FMT_CANON, buf, slen);
	gcry_sexp_release(sig_sexp);

	*sig = buf;
	*sig_len = slen;
	return 0;
}

int
crypto_ecdsa_sign_raw(const unsigned char *key, size_t key_len,
		      const unsigned char *hash, size_t hash_len,
		      unsigned char **sig, size_t * sig_len)
{
	unsigned char *sexp_sig = NULL;
	size_t sexp_sig_len = 0;
	int rc = crypto_ecdsa_sign(key, key_len, hash, hash_len, &sexp_sig,
				   &sexp_sig_len);
	if (rc != 0)
		return -1;

	*sig = NULL;
	*sig_len = 0;

	gcry_sexp_t ss = NULL;
	if (gcry_sexp_new(&ss, sexp_sig, sexp_sig_len, 0) != 0) {
		free(sexp_sig);
		return -1;
	}
	free(sexp_sig);

	/* Navigate: (sig-val (ecdsa|eddsa (r ...) (s ...))) */
	gcry_sexp_t node = gcry_sexp_find_token(ss, "ecdsa", 0);
	if (!node)
		node = gcry_sexp_find_token(ss, "eddsa", 0);
	gcry_sexp_t r_node = NULL, s_node = NULL;
	if (node) {
		r_node = gcry_sexp_find_token(node, "r", 0);
		s_node = gcry_sexp_find_token(node, "s", 0);
		gcry_sexp_release(node);
	}

	if (r_node && s_node) {
		gcry_mpi_t r_mpi =
		    gcry_sexp_nth_mpi(r_node, 1, GCRYMPI_FMT_USG);
		gcry_mpi_t s_mpi =
		    gcry_sexp_nth_mpi(s_node, 1, GCRYMPI_FMT_USG);
		if (r_mpi && s_mpi) {
			size_t rlen = 0, slen = 0;
			gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &rlen, r_mpi);
			gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &slen, s_mpi);
			/* Pad each component to the larger size (fixed-width). */
			size_t half = rlen > slen ? rlen : slen;
			unsigned char *out = calloc(1, half * 2);
			if (out) {
				gcry_mpi_print(GCRYMPI_FMT_USG,
					       out + (half - rlen), rlen, NULL,
					       r_mpi);
				gcry_mpi_print(GCRYMPI_FMT_USG,
					       out + half + (half - slen), slen,
					       NULL, s_mpi);
				*sig = out;
				*sig_len = half * 2;
			}
		}
		gcry_mpi_release(r_mpi);
		gcry_mpi_release(s_mpi);
	}
	gcry_sexp_release(r_node);
	gcry_sexp_release(s_node);
	gcry_sexp_release(ss);

	return *sig ? 0 : -1;
}

/* ECDSA/EdDSA verify. sig is the canonical S-expression produced by crypto_ecdsa_sign. */
int
crypto_ecdsa_verify(const unsigned char *pubkey, size_t pubkey_len,
		    const unsigned char *hash, size_t hash_len,
		    const unsigned char *sig, size_t sig_len)
{
	gcry_sexp_t pub = NULL, data_sexp = NULL, sig_sexp = NULL;
	gcry_error_t err;

	err = gcry_sexp_new(&pub, pubkey, pubkey_len, 0);
	if (err)
		return -1;

	err = gcry_sexp_new(&sig_sexp, sig, sig_len, 0);
	if (err) {
		gcry_sexp_release(pub);
		return -1;
	}

	if (is_eddsa_key(pub)) {
		err = gcry_sexp_build(&data_sexp, NULL,
				      "(data (flags eddsa) (hash-algo sha512) (value %b))",
				      (int)hash_len, hash);
	} else {
		err = gcry_sexp_build(&data_sexp, NULL,
				      "(data (flags raw) (value %b))",
				      (int)hash_len, hash);
	}
	if (err) {
		gcry_sexp_release(sig_sexp);
		gcry_sexp_release(pub);
		return -1;
	}

	err = gcry_pk_verify(sig_sexp, data_sexp, pub);
	gcry_sexp_release(data_sexp);
	gcry_sexp_release(sig_sexp);
	gcry_sexp_release(pub);

	return err ? -1 : 0;
}

/*
 * ECDH derive.  Extracts the peer's Q point from their public-key S-expression
 * and calls gcry_pk_decrypt with an (enc-val (ecdh (e ...))) S-expression.
 */
int
crypto_ecdh_derive(const unsigned char *key, size_t key_len,
		   const unsigned char *peer_pubkey, size_t peer_pubkey_len,
		   unsigned char **secret, size_t * secret_len)
{
	gcry_sexp_t privkey = NULL;
	gcry_sexp_t peer_sexp = NULL, ecc_node = NULL, q_node = NULL;
	gcry_sexp_t enc_sexp = NULL, result = NULL, s_node = NULL;
	gcry_error_t err;
	size_t q_len = 0;
	const char *q_data = NULL;
	size_t slen;
	unsigned char *buf = NULL;

	if (extract_privkey_sexp(key, key_len, &privkey) != 0)
		return -1;

	/* Parse the peer pubkey sexp */
	err = gcry_sexp_new(&peer_sexp, peer_pubkey, peer_pubkey_len, 0);
	if (err) {
		gcry_sexp_release(privkey);
		return -1;
	}

	/* Find the ecc sub-expression */
	ecc_node = gcry_sexp_find_token(peer_sexp, "ecc", 0);
	gcry_sexp_release(peer_sexp);
	if (!ecc_node) {
		gcry_sexp_release(privkey);
		return -1;
	}

	/* Find the q parameter */
	q_node = gcry_sexp_find_token(ecc_node, "q", 0);
	gcry_sexp_release(ecc_node);
	if (!q_node) {
		gcry_sexp_release(privkey);
		return -1;
	}

	q_data = gcry_sexp_nth_data(q_node, 1, &q_len);
	if (!q_data || !q_len) {
		gcry_sexp_release(q_node);
		gcry_sexp_release(privkey);
		return -1;
	}

	/* Build the enc-val sexp for ECDH */
	err = gcry_sexp_build(&enc_sexp, NULL,
			      "(enc-val (ecdh (e %b)))", (int)q_len, q_data);
	gcry_sexp_release(q_node);
	if (err) {
		gcry_sexp_release(privkey);
		return -1;
	}

	err = gcry_pk_decrypt(&result, enc_sexp, privkey);
	gcry_sexp_release(enc_sexp);
	gcry_sexp_release(privkey);
	if (err)
		return -1;

	/* The result is (value #...#); extract the raw bytes */
	s_node = gcry_sexp_find_token(result, "value", 0);
	if (s_node) {
		const char *vdata = gcry_sexp_nth_data(s_node, 1, &slen);
		if (vdata && slen) {
			/*
			 * The ECDH shared secret unwraps a message -- as sensitive
			 * as a private key.  Keep it locked; free via secure_free.
			 */
			buf = secure_alloc(slen);
			if (!buf) {
				gcry_sexp_release(s_node);
				gcry_sexp_release(result);
				return -1;
			}
			memcpy(buf, vdata, slen);
			*secret = buf;
			*secret_len = slen;
			gcry_sexp_release(s_node);
			gcry_sexp_release(result);
			return 0;
		}
		gcry_sexp_release(s_node);
	}

	/*
	 * Fallback: serialize the entire result.  Keep `result` alive until
	 * after the second sprint -- releasing it before the copy would be a
	 * use-after-free.
	 */
	slen = gcry_sexp_sprint(result, GCRYSEXP_FMT_CANON, NULL, 0);
	if (!slen) {
		gcry_sexp_release(result);
		return -1;
	}

	buf = secure_alloc(slen);
	if (!buf) {
		gcry_sexp_release(result);
		return -1;
	}

	gcry_sexp_sprint(result, GCRYSEXP_FMT_CANON, buf, slen);
	gcry_sexp_release(result);
	*secret = buf;
	*secret_len = slen;
	return 0;
}
