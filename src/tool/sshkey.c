/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "sshkey.h"
#include "secmem.h"
#include "bcrypt_pbkdf.h"
#include <gcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- base64 ---- */

static int
b64_val(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

static int
b64_decode(const char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
	unsigned char *buf = malloc(in_len / 4 * 3 + 3);
	if (!buf)
		return -1;
	size_t o = 0;
	unsigned acc = 0;
	int nbits = 0;
	for (size_t i = 0; i < in_len; i++) {
		int c = (unsigned char)in[i];
		if (c == '=')
			break;
		int v = b64_val(c);
		if (v < 0)
			continue;	/* skip newlines and spaces */
		acc = (acc << 6) | (unsigned)v;
		nbits += 6;
		if (nbits >= 8) {
			nbits -= 8;
			buf[o++] = (unsigned char)((acc >> nbits) & 0xff);
			/*
			 * Drop the emitted byte and any bits above the nbits
			 * still pending -- acc is unsigned and stays bounded, so
			 * the shift above never overflows (was a signed int that
			 * grew 6 bits per char until it overran, UBSan-caught).
			 */
			acc &= ((unsigned)1 << nbits) - 1;
		}
	}
	*out = buf;
	*out_len = o;
	return 0;
}

/* ---- file + PEM armor ---- */

static int
read_file(const char *path, char **data, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	char *buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}
	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[rd] = '\0';
	*data = buf;
	*len = rd;
	return 0;
}

/* Extract and base64-decode the openssh-key-v1 blob from a PEM-armored file. */
static int
read_openssh_blob(const char *path, unsigned char **blob, size_t *blob_len)
{
	static const char begin[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
	static const char end[] = "-----END OPENSSH PRIVATE KEY-----";

	char *data = NULL;
	size_t len = 0;
	if (read_file(path, &data, &len) != 0)
		return -1;

	char *b = strstr(data, begin);
	char *e = b ? strstr(b, end) : NULL;
	if (!b || !e) {
		free(data);
		return -1;	/* not an OpenSSH-format key */
	}
	b += sizeof(begin) - 1;
	int rc = b64_decode(b, (size_t)(e - b), blob, blob_len);
	free(data);
	return rc;
}

/* ---- SSH wire buffer readers ---- */

struct sshbuf {
	const unsigned char *p;
	size_t len;
	size_t off;
};

static int
rd_u32(struct sshbuf *b, uint32_t *v)
{
	if (b->len - b->off < 4)
		return -1;
	*v = ((uint32_t)b->p[b->off] << 24)
	    | ((uint32_t)b->p[b->off + 1] << 16)
	    | ((uint32_t)b->p[b->off + 2] << 8)
	    | ((uint32_t)b->p[b->off + 3]);
	b->off += 4;
	return 0;
}

static int
rd_str(struct sshbuf *b, const unsigned char **d, uint32_t *n)
{
	uint32_t l;
	if (rd_u32(b, &l) != 0)
		return -1;
	if (l > b->len - b->off)
		return -1;
	*d = b->p + b->off;
	*n = l;
	b->off += l;
	return 0;
}

/* Compare an SSH string field to a C string. */
static int
str_eq(const unsigned char *d, uint32_t n, const char *s)
{
	return strlen(s) == n && memcmp(d, s, n) == 0;
}

/* ---- per-type sexp builders ---- */

/* pb is positioned just past the keytype string in the private section. */
static int
build_ed25519(struct sshbuf *pb, unsigned char **sexp, size_t *sexp_len,
	      char **algo)
{
	const unsigned char *A, *sk;
	uint32_t alen, sklen;
	if (rd_str(pb, &A, &alen) != 0 || alen != 32)
		return -1;
	if (rd_str(pb, &sk, &sklen) != 0 || sklen != 64)
		return -1;
	/* sk = seed(32) || pubkey(32); gcrypt wants q = 0x40 || A. */
	unsigned char q[33];
	q[0] = 0x40;
	memcpy(q + 1, A, 32);
	gcry_sexp_t s = NULL;
	if (gcry_sexp_build(&s, NULL,
			    "(private-key (ecc (curve \"Ed25519\")"
			    " (flags eddsa) (q %b) (d %b)))",
			    (int)sizeof(q), q, (int)32, sk) != 0)
		return -1;
	int rc = -1;
	if (gcry_pk_testkey(s) == 0) {
		size_t cl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, NULL, 0);
		unsigned char *canon = malloc(cl);
		if (canon) {
			cl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, canon, cl);
			*algo = strdup("ed25519");
			if (*algo) {
				*sexp = canon;
				*sexp_len = cl;
				rc = 0;
			} else {
				free(canon);
			}
		}
	}
	gcry_sexp_release(s);
	return rc;
}

static int
build_rsa(struct sshbuf *pb, unsigned char **sexp, size_t *sexp_len,
	  char **algo)
{
	const unsigned char *N, *E, *D, *IQMP, *P, *Q;
	uint32_t nl, el, dl, il, pl, ql;
	if (rd_str(pb, &N, &nl) || rd_str(pb, &E, &el) || rd_str(pb, &D, &dl)
	    || rd_str(pb, &IQMP, &il) || rd_str(pb, &P, &pl)
	    || rd_str(pb, &Q, &ql))
		return -1;
	(void)IQMP;
	(void)il;
	gcry_mpi_t n = NULL, e = NULL, d = NULL, p = NULL, q = NULL, u = NULL;
	int rc = -1;
	if (gcry_mpi_scan(&n, GCRYMPI_FMT_USG, N, nl, NULL)
	    || gcry_mpi_scan(&e, GCRYMPI_FMT_USG, E, el, NULL)
	    || gcry_mpi_scan(&d, GCRYMPI_FMT_USG, D, dl, NULL)
	    || gcry_mpi_scan(&p, GCRYMPI_FMT_USG, P, pl, NULL)
	    || gcry_mpi_scan(&q, GCRYMPI_FMT_USG, Q, ql, NULL))
		goto out;
	/*
	 * gcrypt requires p < q and u = p^-1 mod q; OpenSSH does not
	 * guarantee the ordering and stores iqmp = q^-1 mod p, so recompute.
	 */
	if (gcry_mpi_cmp(p, q) > 0) {
		gcry_mpi_t t = p;
		p = q;
		q = t;
	}
	u = gcry_mpi_new(0);
	gcry_mpi_invm(u, p, q);
	gcry_sexp_t s = NULL;
	if (gcry_sexp_build(&s, NULL,
			    "(private-key (rsa (n %M)(e %M)(d %M)"
			    "(p %M)(q %M)(u %M)))", n, e, d, p, q, u) != 0)
		goto out;
	if (gcry_pk_testkey(s) == 0) {
		unsigned int nbits = gcry_mpi_get_nbits(n);
		if (nbits < 2048) {
			gcry_sexp_release(s);
			goto out;
		}
		const char *a = nbits <= 2048 ? "rsa2048"
		    : nbits <= 3072 ? "rsa3072" : "rsa4096";
		size_t cl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, NULL, 0);
		unsigned char *canon = malloc(cl);
		if (canon) {
			cl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, canon, cl);
			*algo = strdup(a);
			if (*algo) {
				*sexp = canon;
				*sexp_len = cl;
				rc = 0;
			} else {
				free(canon);
			}
		}
	}
	gcry_sexp_release(s);
 out:
	gcry_mpi_release(n);
	gcry_mpi_release(e);
	gcry_mpi_release(d);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(u);
	return rc;
}

static int
build_ecdsa(struct sshbuf *pb, const unsigned char *kt, uint32_t ktlen,
	    unsigned char **sexp, size_t *sexp_len, char **algo)
{
	const unsigned char *cn, *Q, *Dd;
	uint32_t cl, ql, dl;
	if (rd_str(pb, &cn, &cl) || rd_str(pb, &Q, &ql) || rd_str(pb, &Dd, &dl))
		return -1;
	const char *gcurve, *aname;
	if (str_eq(cn, cl, "nistp256")) {
		gcurve = "NIST P-256";
		aname = "nistp256";
	} else if (str_eq(cn, cl, "nistp384")) {
		gcurve = "NIST P-384";
		aname = "nistp384";
	} else if (str_eq(cn, cl, "nistp521")) {
		gcurve = "NIST P-521";
		aname = "nistp521";
	} else {
		return -1;
	}
	(void)kt;
	(void)ktlen;
	gcry_mpi_t dmpi = NULL;
	if (gcry_mpi_scan(&dmpi, GCRYMPI_FMT_USG, Dd, dl, NULL))
		return -1;
	gcry_sexp_t s = NULL;
	int rc = -1;
	if (gcry_sexp_build(&s, NULL,
			    "(private-key (ecc (curve %s)(q %b)(d %M)))",
			    gcurve, (int)ql, Q, dmpi) == 0) {
		if (gcry_pk_testkey(s) == 0) {
			size_t bl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON,
						     NULL, 0);
			unsigned char *canon = malloc(bl);
			if (canon) {
				bl = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON,
						      canon, bl);
				*algo = strdup(aname);
				if (*algo) {
					*sexp = canon;
					*sexp_len = bl;
					rc = 0;
				} else {
					free(canon);
				}
			}
		}
		gcry_sexp_release(s);
	}
	gcry_mpi_release(dmpi);
	return rc;
}

/* ---- container parsing ---- */

/* Parse the (decrypted) private section: check1==check2, keytype, key. */
static int
parse_private_section(const unsigned char *priv, size_t privlen,
		      unsigned char **sexp, size_t *sexp_len, char **algo)
{
	struct sshbuf pb = { priv, privlen, 0 };
	uint32_t c1, c2;
	if (rd_u32(&pb, &c1) || rd_u32(&pb, &c2) || c1 != c2)
		return -1;	/* wrong passphrase or corrupt */
	const unsigned char *kt;
	uint32_t ktlen;
	if (rd_str(&pb, &kt, &ktlen))
		return -1;
	if (str_eq(kt, ktlen, "ssh-ed25519"))
		return build_ed25519(&pb, sexp, sexp_len, algo);
	if (str_eq(kt, ktlen, "ssh-rsa"))
		return build_rsa(&pb, sexp, sexp_len, algo);
	if (ktlen > 16 && memcmp(kt, "ecdsa-sha2-nistp", 16) == 0)
		return build_ecdsa(&pb, kt, ktlen, sexp, sexp_len, algo);
	return -1;
}

/*
 * Decrypt the aes256-ctr/bcrypt private section in place into *out (malloc'd).
 * Returns 0 on success, -1 on unsupported cipher/kdf or error.
 */
static int
decrypt_private(const unsigned char *cipher, uint32_t cipherlen,
		const unsigned char *kdf, uint32_t kdflen,
		const unsigned char *kdfopts, uint32_t kdfoptlen,
		const unsigned char *priv, uint32_t privlen,
		const char *passphrase,
		unsigned char **out)
{
	if (!str_eq(cipher, cipherlen, "aes256-ctr")
	    || !str_eq(kdf, kdflen, "bcrypt") || !passphrase)
		return -1;
	if (privlen == 0 || (privlen % 16) != 0)
		return -1;

	/* kdfoptions = string salt || uint32 rounds */
	struct sshbuf ko = { kdfopts, kdfoptlen, 0 };
	const unsigned char *salt;
	uint32_t saltlen, rounds;
	if (rd_str(&ko, &salt, &saltlen) || rd_u32(&ko, &rounds) || rounds == 0)
		return -1;

	unsigned char keyiv[48];	/* 32 key + 16 IV */
	if (bcrypt_pbkdf(passphrase, strlen(passphrase), salt, saltlen,
			 keyiv, sizeof(keyiv), rounds) != 0) {
		secure_zero(keyiv, sizeof(keyiv));
		return -1;
	}

	unsigned char *buf = malloc(privlen);
	if (!buf) {
		secure_zero(keyiv, sizeof(keyiv));
		return -1;
	}
	gcry_cipher_hd_t h = NULL;
	int rc = -1;
	if (gcry_cipher_open(&h, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0)
	    == 0
	    && gcry_cipher_setkey(h, keyiv, 32) == 0
	    && gcry_cipher_setctr(h, keyiv + 32, 16) == 0
	    && gcry_cipher_decrypt(h, buf, privlen, priv, privlen) == 0)
		rc = 0;
	if (h)
		gcry_cipher_close(h);
	secure_zero(keyiv, sizeof(keyiv));
	if (rc != 0) {
		secure_zero(buf, privlen);
		free(buf);
		return -1;
	}
	*out = buf;
	return 0;
}

static int
parse_blob(const unsigned char *blob, size_t blob_len, const char *passphrase,
	   unsigned char **sexp, size_t *sexp_len, char **algo)
{
	static const char magic[] = "openssh-key-v1";	/* 15 incl NUL */
	if (blob_len < 15 || memcmp(blob, magic, 15) != 0)
		return -1;
	struct sshbuf b = { blob + 15, blob_len - 15, 0 };
	const unsigned char *cipher, *kdf, *kdfopts, *pub, *priv;
	uint32_t cipherlen, kdflen, kdfoptlen, nkeys, publen, privlen;
	if (rd_str(&b, &cipher, &cipherlen) || rd_str(&b, &kdf, &kdflen)
	    || rd_str(&b, &kdfopts, &kdfoptlen) || rd_u32(&b, &nkeys))
		return -1;
	if (nkeys != 1)
		return -1;
	if (rd_str(&b, &pub, &publen) || rd_str(&b, &priv, &privlen))
		return -1;
	(void)pub; (void)publen;

	if (str_eq(cipher, cipherlen, "none"))
		return parse_private_section(priv, privlen, sexp, sexp_len, algo);

	unsigned char *dec = NULL;
	if (decrypt_private(cipher, cipherlen, kdf, kdflen, kdfopts, kdfoptlen,
			    priv, privlen, passphrase, &dec) != 0)
		return -1;
	int rc = parse_private_section(dec, privlen, sexp, sexp_len, algo);
	secure_zero(dec, privlen);
	free(dec);
	return rc;
}

int
sshkey_is_encrypted(const char *path)
{
	unsigned char *blob = NULL;
	size_t blob_len = 0;
	if (read_openssh_blob(path, &blob, &blob_len) != 0)
		return -1;
	int enc = -1;
	if (blob_len >= 15 && memcmp(blob, "openssh-key-v1", 15) == 0) {
		struct sshbuf b = { blob + 15, blob_len - 15, 0 };
		const unsigned char *cipher;
		uint32_t cipherlen;
		if (rd_str(&b, &cipher, &cipherlen) == 0)
			enc = str_eq(cipher, cipherlen, "none") ? 0 : 1;
	}
	free(blob);
	return enc;
}

int
sshkey_load(const char *path, const char *passphrase,
	    unsigned char **sexp, size_t *sexp_len, char **algo)
{
	unsigned char *blob = NULL;
	size_t blob_len = 0;
	if (read_openssh_blob(path, &blob, &blob_len) != 0)
		return -1;
	int rc = parse_blob(blob, blob_len, passphrase, sexp, sexp_len, algo);
	secure_zero(blob, blob_len);
	free(blob);
	return rc == 0 ? 0 : -1;
}
