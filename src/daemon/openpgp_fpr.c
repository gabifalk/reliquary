/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "openpgp_fpr.h"

#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

/* OpenPGP public-key algorithm ids (RFC 4880 sec. 9.1 / RFC 6637). */
#define PGP_ALGO_RSA    1
#define PGP_ALGO_ECDH  18
#define PGP_ALGO_ECDSA 19
#define PGP_ALGO_EDDSA 22

/*
 * Curve OIDs (the OID value octets, no tag/length) and, for ECDH, gpg's default
 * KDF parameters "03 01 <KEK-hash> <KEK-cipher>".  The hash/cipher pairs are
 * what gpg actually emits (verified against generated keys), not RFC 6637's
 * matching-strength suggestion: 256-bit -> SHA-256/AES-128, 384-bit ->
 * SHA-384/AES-256, 521-bit -> SHA-512/AES-256.
 */
static const unsigned char OID_NISTP256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const unsigned char OID_NISTP384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const unsigned char OID_NISTP521[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };
static const unsigned char OID_ED25519[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };
static const unsigned char KDF_256[] = { 0x03, 0x01, 0x08, 0x07 };
static const unsigned char KDF_384[] = { 0x03, 0x01, 0x09, 0x09 };
static const unsigned char KDF_521[] = { 0x03, 0x01, 0x0A, 0x09 };

struct ec_params {
	const char *algo;
	const unsigned char *oid;
	size_t oid_len;
	const unsigned char *kdf;	/* ECDH default KDF params, sign/auth use none */
	size_t kdf_len;
	int eddsa;			/* EdDSA (sign only), never ECDH */
};

static const struct ec_params EC_TABLE[] = {
	{ "nistp256", OID_NISTP256, sizeof OID_NISTP256, KDF_256, sizeof KDF_256, 0 },
	{ "nistp384", OID_NISTP384, sizeof OID_NISTP384, KDF_384, sizeof KDF_384, 0 },
	{ "nistp521", OID_NISTP521, sizeof OID_NISTP521, KDF_521, sizeof KDF_521, 0 },
	{ "ed25519", OID_ED25519, sizeof OID_ED25519, NULL, 0, 1 },
};

/*
 * Append raw big-endian bytes as an OpenPGP MPI (2-octet bit count + value,
 * leading zero octets dropped).
 */
static size_t
append_mpi_bytes(unsigned char *buf, size_t off, size_t cap,
		 const unsigned char *v, size_t vlen)
{
	while (vlen && *v == 0) {
		v++;
		vlen--;
	}
	unsigned int nbits = 0;
	if (vlen) {
		unsigned int top = 0;
		for (int i = 7; i >= 0; i--)
			if (v[0] & (1u << i)) {
				top = (unsigned int)i + 1;
				break;
			}
		nbits = (unsigned int)(vlen - 1) * 8 + top;
	}
	if (off + 2 + vlen > cap)
		return cap + 1;	/* signal overflow */
	buf[off++] = (unsigned char)(nbits >> 8);
	buf[off++] = (unsigned char)(nbits & 0xff);
	memcpy(buf + off, v, vlen);
	return off + vlen;
}

/* Append the RSA public fields MPI(n) || MPI(e). */
static size_t
append_rsa(unsigned char *buf, size_t off, size_t cap, gcry_sexp_t rsa)
{
	gcry_sexp_t nn = gcry_sexp_find_token(rsa, "n", 0);
	gcry_sexp_t ee = gcry_sexp_find_token(rsa, "e", 0);
	size_t out = cap + 1;
	if (nn && ee) {
		size_t nl = 0, el = 0;
		const char *nd = gcry_sexp_nth_data(nn, 1, &nl);
		const char *ed = gcry_sexp_nth_data(ee, 1, &el);
		if (nd && ed) {
			off = append_mpi_bytes(buf, off, cap,
					       (const unsigned char *)nd, nl);
			if (off <= cap)
				off = append_mpi_bytes(buf, off, cap,
						(const unsigned char *)ed, el);
			out = off;
		}
	}
	gcry_sexp_release(nn);
	gcry_sexp_release(ee);
	return out;
}

int
openpgp_v4_fpr(const char *algo, int slot, uint32_t created,
	       const unsigned char *pubkey_canon, size_t pubkey_len,
	       char *out_hex, size_t out_sz)
{
	gcry_sexp_t pk = NULL, alg = NULL;
	gcry_md_hd_t md = NULL;
	unsigned char body[1200];
	size_t bl = 0;
	int algo_id = 0;
	int ret = -1;

	if (out_sz < 41 || !algo)
		return -1;
	if (gcry_sexp_new(&pk, pubkey_canon, pubkey_len, 0))
		return -1;

	body[bl++] = 0x04;
	body[bl++] = (unsigned char)(created >> 24);
	body[bl++] = (unsigned char)(created >> 16);
	body[bl++] = (unsigned char)(created >> 8);
	body[bl++] = (unsigned char)(created);
	body[bl++] = 0;		/* algorithm id, filled in below */

	if (strncmp(algo, "rsa", 3) == 0) {
		alg = gcry_sexp_find_token(pk, "rsa", 0);
		if (!alg)
			goto out;
		algo_id = PGP_ALGO_RSA;
		bl = append_rsa(body, bl, sizeof body, alg);
	} else {
		const struct ec_params *p = NULL;
		for (size_t i = 0; i < sizeof EC_TABLE / sizeof EC_TABLE[0]; i++)
			if (strcmp(algo, EC_TABLE[i].algo) == 0) {
				p = &EC_TABLE[i];
				break;
			}
		if (!p)
			goto out;
		alg = gcry_sexp_find_token(pk, "ecc", 0);
		gcry_sexp_t q = alg ? gcry_sexp_find_token(alg, "q", 0) : NULL;
		if (!q)
			goto out;
		int ecdh = !p->eddsa && slot == 1;	/* encrypt slot */
		algo_id = p->eddsa ? PGP_ALGO_EDDSA
		    : ecdh ? PGP_ALGO_ECDH : PGP_ALGO_ECDSA;
		/* curve OID: length octet + value */
		if (bl + 1 + p->oid_len > sizeof body) {
			gcry_sexp_release(q);
			goto out;
		}
		body[bl++] = (unsigned char)p->oid_len;
		memcpy(body + bl, p->oid, p->oid_len);
		bl += p->oid_len;
		size_t qlen = 0;
		const char *qd = gcry_sexp_nth_data(q, 1, &qlen);
		if (qd)
			bl = append_mpi_bytes(body, bl, sizeof body,
					      (const unsigned char *)qd, qlen);
		gcry_sexp_release(q);
		if (ecdh && bl <= sizeof body) {
			if (bl + p->kdf_len > sizeof body)
				goto out;
			memcpy(body + bl, p->kdf, p->kdf_len);
			bl += p->kdf_len;
		}
	}
	if (bl > sizeof body || bl > 0xffff)
		goto out;
	body[5] = (unsigned char)algo_id;

	unsigned char hdr[3] = { 0x99, (unsigned char)(bl >> 8),
				 (unsigned char)(bl & 0xff) };
	if (gcry_md_open(&md, GCRY_MD_SHA1, 0))
		goto out;
	gcry_md_write(md, hdr, sizeof hdr);
	gcry_md_write(md, body, bl);
	const unsigned char *dig = gcry_md_read(md, GCRY_MD_SHA1);
	if (dig) {
		for (int i = 0; i < 20; i++)
			snprintf(out_hex + 2 * i, 3, "%02X", dig[i]);
		out_hex[40] = '\0';
		ret = 0;
	}

out:
	if (md)
		gcry_md_close(md);
	gcry_sexp_release(alg);
	gcry_sexp_release(pk);
	return ret;
}
