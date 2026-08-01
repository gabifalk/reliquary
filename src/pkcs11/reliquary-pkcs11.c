/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "pkcs11.h"
#include "client.h"
#include "hex.h"
#include "meta.h"

#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SESSION_BASE    0xBEEF0000
#define SESSION_HANDLE(slot) ((CK_SESSION_HANDLE)(SESSION_BASE + (slot)))
#define SESSION_TO_SLOT(h) ((CK_SLOT_ID)((h) - SESSION_BASE))
#define SESSION_VALID(h) ((h) >= SESSION_BASE && SESSION_TO_SLOT(h) < g.num_slots)
#define MAX_SLOTS       64

/* Object handles encode: pkcs11_slot (which token) + key_slot (0-2) + type (priv/pub) */
#define OBJ_HANDLE(pslot, kslot, is_priv) \
    ((CK_OBJECT_HANDLE)((pslot) * 6 + (kslot) * 2 + ((is_priv) ? 1 : 2)))
#define OBJ_PSLOT(h)    (((h) - 1) / 6)
#define OBJ_KSLOT(h)    ((((h) - 1) % 6) / 2)
#define OBJ_IS_PRIV(h)  (((h) - 1) % 2 == 0)

/*
 * Derived secret-key objects (C_DeriveKey / ECDH) live only for the session.
 * The token key objects above are stateless -- their handle encodes which key
 * they are -- but a derived secret has bytes to hold, so it needs backing
 * storage.  Handles live in a distinct high range so C_GetAttributeValue can
 * tell them apart from the encoded token-key handles.  DERIVED_HANDLE packs the
 * owning pkcs11 slot and an index into that slot's derived[] table.
 */
#define MAX_DERIVED     8
#define DERIVED_BASE    ((CK_OBJECT_HANDLE)0x100000)
#define DERIVED_HANDLE(pslot, idx) \
    ((CK_OBJECT_HANDLE)(DERIVED_BASE + (pslot) * MAX_DERIVED + (idx)))
#define IS_DERIVED_HANDLE(h)    ((h) >= DERIVED_BASE)
#define DERIVED_PSLOT(h)        (((h) - DERIVED_BASE) / MAX_DERIVED)
#define DERIVED_IDX(h)          (((h) - DERIVED_BASE) % MAX_DERIVED)

/* ---------- global state ---------- */

static struct {
	int initialized;
	assuan_context_t daemon;	/* connection for slot enumeration (C_Initialize) */

	struct {
		char label[33];
		char serial[33];	/* cached CK_TOKEN_INFO.serialNumber source */
		/* Per-OpenPGP-slot key data (3 slots: sign, encrypt, auth) */
		char algorithm[3][32];
		unsigned char *pubkey_raw[3];	/* raw S-expression bytes */
		size_t pubkey_raw_len[3];
		/* Per-session state */
		assuan_context_t conn;	/* per-slot daemon connection */
		int session_open;
		int logged_in;
		int pending_op;	/* 0=none, 1=sign, 2=decrypt */
		CK_MECHANISM_TYPE pending_mech;
		int pending_kslot;	/* which OpenPGP key slot for pending op */
		/* multi-part sign buffer */
		unsigned char *sign_buf;
		size_t sign_buf_len;
		size_t sign_buf_cap;
		/* find state */
		int find_active;
		CK_OBJECT_CLASS find_class;	/* 0 = any */
		int find_returned;
		/* derived (ECDH) secret-key session objects */
		struct {
			int in_use;
			unsigned char *value;
			size_t value_len;
		} derived[MAX_DERIVED];
	} slots[MAX_SLOTS];
	CK_ULONG num_slots;

	/* Mechanism list, as reported by the daemon (authoritative). */
	CK_MECHANISM_TYPE mech_list[16];
	CK_ULONG mech_count;
} g;

/* ---------- helpers ---------- */

/*
 * Map a numeric mechanism, together with the operation it is being used for,
 * to its dotted wire token.  op: 0=sign 1=decrypt 2=derive.  Returns NULL if
 * unsupported.  CKM_RSA_PKCS is operation-qualified since the daemon
 * advertises and dispatches sign.rsa-pkcs1 and decrypt.rsa-pkcs1 as distinct
 * tokens even though they share one numeric PKCS#11 mechanism.
 */
static const char *
wire_mech(int op, CK_MECHANISM_TYPE m)
{
	switch (m) {
	case CKM_RSA_PKCS:
		return op == 0 ? "sign.rsa-pkcs1" : "decrypt.rsa-pkcs1";
	case CKM_RSA_PKCS_PSS:
		return "sign.rsa-pss";
	case CKM_RSA_PKCS_OAEP:
		return "decrypt.rsa-oaep";
	case CKM_RSA_X_509:
		return op == 1 ? "decrypt.rsa-raw" : NULL;
	case CKM_ECDSA:
		return "sign.ecdsa";
	case CKM_EDDSA:
		return "sign.eddsa";
	case CKM_ECDH1_DERIVE:
		return "derive.ecdh";
	default:
		return NULL;
	}
}

/*
 * Reverse of wire_mech(): map a daemon-reported dotted mechanism token to its
 * CK_MECHANISM_TYPE.  Returns 1 and sets *out on success, 0 if unknown.
 */
static int
mech_type(const char *name, CK_MECHANISM_TYPE * out)
{
	if (strcmp(name, "sign.rsa-pkcs1") == 0 ||
	    strcmp(name, "decrypt.rsa-pkcs1") == 0) {
		*out = CKM_RSA_PKCS;
		return 1;
	}
	if (strcmp(name, "sign.rsa-pss") == 0) {
		*out = CKM_RSA_PKCS_PSS;
		return 1;
	}
	if (strcmp(name, "decrypt.rsa-oaep") == 0) {
		*out = CKM_RSA_PKCS_OAEP;
		return 1;
	}
	if (strcmp(name, "decrypt.rsa-raw") == 0) {
		*out = CKM_RSA_X_509;
		return 1;
	}
	if (strcmp(name, "sign.ecdsa") == 0) {
		*out = CKM_ECDSA;
		return 1;
	}
	if (strcmp(name, "sign.eddsa") == 0) {
		*out = CKM_EDDSA;
		return 1;
	}
	if (strcmp(name, "derive.ecdh") == 0) {
		*out = CKM_ECDH1_DERIVE;
		return 1;
	}
	return 0;
}

/*
 * Release all derived (ECDH) secret-key objects held by a pkcs11 slot.
 * Called from every session-teardown path, mirroring the sign_buf cleanup.
 */
static void
free_derived(CK_SLOT_ID slot)
{
	for (int i = 0; i < MAX_DERIVED; i++) {
		free(g.slots[slot].derived[i].value);
		g.slots[slot].derived[i].value = NULL;
		g.slots[slot].derived[i].value_len = 0;
		g.slots[slot].derived[i].in_use = 0;
	}
}

static void
pad_copy(CK_UTF8CHAR * dst, size_t dst_len, const char *src)
{
	size_t slen = strlen(src);
	if (slen > dst_len)
		slen = dst_len;
	memcpy(dst, src, slen);
	if (slen < dst_len)
		memset(dst + slen, ' ', dst_len - slen);
}

/*
 * Query the daemon's authoritative mechanism list and cache the parsed
 * CK_MECHANISM_TYPEs in g.  The daemon is the single source of truth;
 * on any failure the cache is left empty rather than guessed at.
 */
static void
refresh_mechanisms(void)
{
	g.mech_count = 0;

	char *data = NULL;
	size_t len = 0;
	if (client_command(g.daemon, "GET_MECHANISM_LIST", &data, &len) != 0
	    || !data || len == 0) {
		free(data);
		return;
	}

	char *buf = malloc(len + 1);
	if (!buf) {
		free(data);
		return;
	}
	memcpy(buf, data, len);
	buf[len] = '\0';
	free(data);

	size_t max_mechs = sizeof(g.mech_list) / sizeof(g.mech_list[0]);
	char *line = buf;
	while (line && *line && g.mech_count < max_mechs) {
		char *nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		if (*line) {
			CK_MECHANISM_TYPE t;
			if (mech_type(line, &t)) {
				int dup = 0;
				for (CK_ULONG j = 0; j < g.mech_count; j++)
					if (g.mech_list[j] == t) {
						dup = 1;
						break;
					}
				if (!dup && g.mech_count < max_mechs)
					g.mech_list[g.mech_count++] = t;
			}
		}
		line = nl ? nl + 1 : NULL;
	}

	free(buf);
}

static gpg_error_t
list_tokens_status_cb(void *opaque, const char *line)
{
	(void)opaque;
	/* line: "TOKEN <serial> <label> <status>" */
	if (strncmp(line, "TOKEN ", 6) != 0)
		return 0;
	const char *p = line + 6;

	char serial[64];
	int si = 0;
	while (*p && *p != ' ' && si < (int)sizeof(serial) - 1)
		serial[si++] = *p++;
	serial[si] = '\0';
	while (*p == ' ')
		p++;

	char label[33];
	int li = 0;
	while (*p && *p != ' ' && li < (int)sizeof(label) - 1)
		label[li++] = *p++;
	label[li] = '\0';
	while (*p == ' ')
		p++;

	if (strcmp(p, "disconnected") == 0)
		return 0;	/* skip disconnected tokens */
	if (g.num_slots >= MAX_SLOTS)
		return 0;

	memcpy(g.slots[g.num_slots].label, label, strlen(label) + 1);
	for (int k = 0; k < 3; k++)
		g.slots[g.num_slots].algorithm[k][0] = '\0';
	strncpy(g.slots[g.num_slots].serial, serial,
		sizeof(g.slots[g.num_slots].serial) - 1);
	g.slots[g.num_slots].serial[sizeof(g.slots[g.num_slots].serial) - 1] =
	    '\0';
	g.num_slots++;
	return 0;
}

static int
refresh_slots(void)
{
	refresh_mechanisms();
	g.num_slots = 0;
	gpg_error_t err = client_command_status(g.daemon, "LIST_TOKENS",
						list_tokens_status_cb, NULL);
	if (err)
		return -1;
	return 0;
}

static void
free_slot_pubkey(CK_SLOT_ID slot)
{
	for (int i = 0; i < 3; i++) {
		free(g.slots[slot].pubkey_raw[i]);
		g.slots[slot].pubkey_raw[i] = NULL;
		g.slots[slot].pubkey_raw_len[i] = 0;
	}
}

/* Fetch public key hex from daemon, decode to raw S-expression bytes. */
static void
fetch_slot_pubkey(CK_SLOT_ID slot, int key_slot)
{
	free(g.slots[slot].pubkey_raw[key_slot]);
	g.slots[slot].pubkey_raw[key_slot] = NULL;
	g.slots[slot].pubkey_raw_len[key_slot] = 0;

	char cmd[128];
	snprintf(cmd, sizeof(cmd), "GET_ATTRIBUTE public_key.%d", key_slot);

	char *data = NULL;
	size_t len = 0;
	if (client_command(g.slots[slot].conn, cmd, &data, &len) != 0
	    || !data || len == 0) {
		free(data);
		return;
	}

	/* null-terminate the hex string */
	char *hex = malloc(len + 1);
	if (!hex) {
		free(data);
		return;
	}
	memcpy(hex, data, len);
	hex[len] = '\0';
	free(data);

	/* trim whitespace */
	size_t hlen = strlen(hex);
	while (hlen > 0 && (hex[hlen - 1] == '\n' || hex[hlen - 1] == ' '))
		hex[--hlen] = '\0';

	/* decode hex to raw bytes */
	unsigned char *raw = malloc(hlen / 2 + 1);
	size_t raw_len = 0;
	if (!raw || hex_decode(hex, raw, hlen / 2 + 1, &raw_len) != 0) {
		free(hex);
		free(raw);
		return;
	}
	free(hex);

	g.slots[slot].pubkey_raw[key_slot] = raw;
	g.slots[slot].pubkey_raw_len[key_slot] = raw_len;
}

/*
 * Find a parameter sub-node in a public key S-expression.
 * e.g. ("rsa", "n") finds n inside (public-key (rsa (n VALUE)))
 */
static gcry_sexp_t
sexp_find_param(const unsigned char *sexp_buf, size_t sexp_len,
		const char *alg_token, const char *param_name)
{
	gcry_sexp_t sexp = NULL, alg = NULL, param = NULL;

	if (gcry_sexp_new(&sexp, sexp_buf, sexp_len, 0) != 0)
		return NULL;

	alg = gcry_sexp_find_token(sexp, alg_token, 0);
	gcry_sexp_release(sexp);
	if (!alg)
		return NULL;

	param = gcry_sexp_find_token(alg, param_name, 0);
	gcry_sexp_release(alg);
	return param;
}

/*
 * Extract an MPI as unsigned big-endian bytes (no sign padding).
 * Use for RSA n, e.  Returns malloc'd buffer, caller frees.
 */
static unsigned char *
sexp_extract_mpi(const unsigned char *sexp_buf, size_t sexp_len,
		 const char *alg_token, const char *param_name,
		 size_t * out_len)
{
	gcry_sexp_t param = sexp_find_param(sexp_buf, sexp_len,
					    alg_token, param_name);
	if (!param)
		return NULL;

	gcry_mpi_t mpi = gcry_sexp_nth_mpi(param, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(param);
	if (!mpi)
		return NULL;

	unsigned char *result = NULL;
	size_t len = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	if (len > 0) {
		result = malloc(len);
		if (result)
			gcry_mpi_print(GCRYMPI_FMT_USG, result, len, out_len,
				       mpi);
	}
	gcry_mpi_release(mpi);
	return result;
}

/*
 * Extract raw byte data from an S-expression parameter.
 * Use for EC point (q) which is not an MPI.
 * Returns malloc'd buffer, caller frees.
 */
static unsigned char *
sexp_extract_raw(const unsigned char *sexp_buf, size_t sexp_len,
		 const char *alg_token, const char *param_name,
		 size_t * out_len)
{
	gcry_sexp_t param = sexp_find_param(sexp_buf, sexp_len,
					    alg_token, param_name);
	if (!param)
		return NULL;

	size_t len = 0;
	const char *data = gcry_sexp_nth_data(param, 1, &len);
	unsigned char *result = NULL;
	if (data && len > 0) {
		result = malloc(len);
		if (result) {
			memcpy(result, data, len);
			*out_len = len;
		}
	}
	gcry_sexp_release(param);
	return result;
}

/* ---------- stub ---------- */

static CK_RV
stub_not_supported(void)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Cast the generic stub to a specific PKCS#11 function pointer type. */
#define STUB(type) ((type) (void (*)(void)) stub_not_supported)

/* ---------- core implementations ---------- */

static CK_RV
impl_Initialize(CK_VOID_PTR pInitArgs)
{
	(void)pInitArgs;
	if (g.initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (client_connect(&g.daemon) != 0)
		return CKR_GENERAL_ERROR;

	if (refresh_slots() != 0) {
		client_disconnect(g.daemon);
		return CKR_GENERAL_ERROR;
	}

	g.initialized = 1;
	return CKR_OK;
}

static CK_RV
impl_Finalize(CK_VOID_PTR pReserved)
{
	(void)pReserved;
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	for (CK_ULONG i = 0; i < g.num_slots; i++) {
		if (g.slots[i].session_open) {
			client_command_ok(g.slots[i].conn, "CLOSE_SESSION");
			client_disconnect(g.slots[i].conn);
			g.slots[i].conn = NULL;
			g.slots[i].session_open = 0;
		}
		free(g.slots[i].sign_buf);
		free_derived(i);
		free_slot_pubkey(i);
	}

	client_disconnect(g.daemon);
	memset(&g, 0, sizeof(g));
	return CKR_OK;
}

static CK_RV
impl_GetInfo(CK_INFO * pInfo)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->cryptokiVersion.major = 3;
	pInfo->cryptokiVersion.minor = 0;
	pad_copy(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
		 "Reliquary");
	pInfo->flags = 0;
	pad_copy(pInfo->libraryDescription, sizeof(pInfo->libraryDescription),
		 "Reliquary PKCS#11");
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 1;
	return CKR_OK;
}

static CK_RV
impl_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID * pSlotList,
		 CK_ULONG * pulCount)
{
	(void)tokenPresent;
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;

	if (!pSlotList) {
		*pulCount = g.num_slots;
		return CKR_OK;
	}

	if (*pulCount < g.num_slots) {
		*pulCount = g.num_slots;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (CK_ULONG i = 0; i < g.num_slots; i++)
		pSlotList[i] = i;
	*pulCount = g.num_slots;
	return CKR_OK;
}

static CK_RV
impl_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO * pInfo)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof(*pInfo));
	pad_copy(pInfo->slotDescription, sizeof(pInfo->slotDescription),
		 g.slots[slotID].label);
	pad_copy(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
		 "Reliquary");
	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 1;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 1;
	return CKR_OK;
}

static CK_RV
impl_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO * pInfo)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof(*pInfo));
	pad_copy(pInfo->label, sizeof(pInfo->label), g.slots[slotID].label);
	pad_copy(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
		 "Reliquary");
	pad_copy(pInfo->model, sizeof(pInfo->model), "Software");
	/*
	 * pInfo->serialNumber is a fixed 16-byte field, but the canonical
	 * serial (reliquary_format_serial()) is a 32-character hex AID whose
	 * per-token distinguishing part is the 4-byte serial field at hex
	 * chars 20..27 -- the first 16 ("D276000124010300") are the fixed
	 * OpenPGP AID prefix shared by every token.  Copying the head (as a
	 * naive pad_copy of the full string would) truncates away the varying
	 * serial field, so copy the *last* 16 chars instead: that window
	 * ("FFFF" + serial + RFU) still contains the serial field and keeps
	 * tokens distinguishable.
	 */
	{
		const char *ser = g.slots[slotID].serial;
		size_t serlen = strlen(ser);
		if (serlen == 0)
			pad_copy(pInfo->serialNumber,
				 sizeof(pInfo->serialNumber), "0000");
		else
			pad_copy(pInfo->serialNumber,
				 sizeof(pInfo->serialNumber),
				 serlen > sizeof(pInfo->serialNumber)
				 ? ser + (serlen - sizeof(pInfo->serialNumber))
				 : ser);
	}
	pInfo->flags = CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = 1;
	pInfo->ulSessionCount = g.slots[slotID].session_open ? 1 : 0;
	pInfo->ulMaxRwSessionCount = 1;
	pInfo->ulRwSessionCount = g.slots[slotID].session_open ? 1 : 0;
	pInfo->ulMaxPinLen = 256;
	pInfo->ulMinPinLen = 1;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 1;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 1;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
	return CKR_OK;
}

static CK_RV
impl_GetMechanismList(CK_SLOT_ID slotID,
		      CK_MECHANISM_TYPE * pMechanismList, CK_ULONG * pulCount)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;

	/*
	 * The mechanism list is cached from the daemon (authoritative
	 * source) at refresh_slots() time -- see refresh_mechanisms().
	 */
	CK_ULONG count = g.mech_count;

	if (!pMechanismList) {
		*pulCount = count;
		return CKR_OK;
	}

	if (*pulCount < count) {
		*pulCount = count;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(pMechanismList, g.mech_list, count * sizeof(CK_MECHANISM_TYPE));
	*pulCount = count;
	return CKR_OK;
}

static CK_RV
impl_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
		      CK_MECHANISM_INFO * pInfo)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof(*pInfo));

	switch (type) {
	case CKM_RSA_PKCS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 4096;
		pInfo->flags = CKF_SIGN | CKF_DECRYPT;
		break;
	case CKM_RSA_PKCS_PSS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 4096;
		pInfo->flags = CKF_SIGN;
		break;
	case CKM_RSA_PKCS_OAEP:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 4096;
		pInfo->flags = CKF_DECRYPT;
		break;
	case CKM_ECDSA:
		pInfo->ulMinKeySize = 256;
		pInfo->ulMaxKeySize = 521;
		pInfo->flags = CKF_SIGN;
		break;
	case CKM_EDDSA:
		pInfo->ulMinKeySize = 256;
		pInfo->ulMaxKeySize = 256;
		pInfo->flags = CKF_SIGN;
		break;
	case CKM_ECDH1_DERIVE:
		pInfo->ulMinKeySize = 256;
		pInfo->ulMaxKeySize = 521;
		pInfo->flags = CKF_DERIVE;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}

static CK_RV
impl_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
		 CK_VOID_PTR pApplication, CK_NOTIFY Notify,
		 CK_SESSION_HANDLE * phSession)
{
	(void)pApplication;
	(void)Notify;
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_ARGUMENTS_BAD;
	if (!phSession)
		return CKR_ARGUMENTS_BAD;

	if (g.slots[slotID].session_open) {
		/* Already open on this slot -- close first */
		client_command_ok(g.slots[slotID].conn, "CLOSE_SESSION");
		client_disconnect(g.slots[slotID].conn);
		g.slots[slotID].conn = NULL;
		g.slots[slotID].session_open = 0;
		g.slots[slotID].logged_in = 0;
		g.slots[slotID].pending_op = 0;
		g.slots[slotID].find_active = 0;
		free(g.slots[slotID].sign_buf);
		g.slots[slotID].sign_buf = NULL;
		g.slots[slotID].sign_buf_len = 0;
		g.slots[slotID].sign_buf_cap = 0;
		free_derived(slotID);
	}

	/* Connect to daemon for this slot's session */
	if (client_connect(&g.slots[slotID].conn) != 0)
		return CKR_GENERAL_ERROR;

	char cmd[128];
	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", g.slots[slotID].label);
	if (client_command_ok(g.slots[slotID].conn, cmd) != 0) {
		client_disconnect(g.slots[slotID].conn);
		g.slots[slotID].conn = NULL;
		return CKR_GENERAL_ERROR;
	}

	/* Fetch algorithm and public key for all 3 OpenPGP key slots */
	for (int ks = 0; ks < 3; ks++) {
		char acmd[128];
		snprintf(acmd, sizeof(acmd), "GET_ATTRIBUTE algorithm.%d", ks);
		char *data = NULL;
		size_t len = 0;
		gpg_error_t err =
		    client_command(g.slots[slotID].conn, acmd, &data, &len);
		if (!err && data && len > 0) {
			size_t clen =
			    len < sizeof(g.slots[slotID].algorithm[ks]) - 1
			    ? len : sizeof(g.slots[slotID].algorithm[ks]) - 1;
			memcpy(g.slots[slotID].algorithm[ks], data, clen);
			g.slots[slotID].algorithm[ks][clen] = '\0';
			while (clen > 0
			       && (g.slots[slotID].algorithm[ks][clen - 1] ==
				   '\n'
				   || g.slots[slotID].algorithm[ks][clen - 1] ==
				   ' ')) {
				g.slots[slotID].algorithm[ks][--clen] = '\0';
			}
		} else {
			g.slots[slotID].algorithm[ks][0] = '\0';
		}
		free(data);

		fetch_slot_pubkey(slotID, ks);
	}

	g.slots[slotID].session_open = 1;
	g.slots[slotID].logged_in = 0;
	g.slots[slotID].pending_op = 0;
	g.slots[slotID].find_active = 0;
	*phSession = SESSION_HANDLE(slotID);
	return CKR_OK;
}

static CK_RV
impl_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;

	client_command_ok(g.slots[slot].conn, "CLOSE_SESSION");
	client_disconnect(g.slots[slot].conn);
	g.slots[slot].conn = NULL;
	g.slots[slot].session_open = 0;
	g.slots[slot].logged_in = 0;
	g.slots[slot].pending_op = 0;
	g.slots[slot].find_active = 0;
	free(g.slots[slot].sign_buf);
	g.slots[slot].sign_buf = NULL;
	g.slots[slot].sign_buf_len = 0;
	g.slots[slot].sign_buf_cap = 0;
	free_derived(slot);
	return CKR_OK;
}

static CK_RV
impl_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g.num_slots)
		return CKR_SLOT_ID_INVALID;

	if (g.slots[slotID].session_open) {
		client_command_ok(g.slots[slotID].conn, "CLOSE_SESSION");
		client_disconnect(g.slots[slotID].conn);
		g.slots[slotID].conn = NULL;
		g.slots[slotID].session_open = 0;
		g.slots[slotID].logged_in = 0;
		g.slots[slotID].pending_op = 0;
		g.slots[slotID].find_active = 0;
		free(g.slots[slotID].sign_buf);
		g.slots[slotID].sign_buf = NULL;
		g.slots[slotID].sign_buf_len = 0;
		g.slots[slotID].sign_buf_cap = 0;
		free_derived(slotID);
	}
	return CKR_OK;
}

static CK_RV
impl_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO * pInfo)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->slotID = slot;
	pInfo->state =
	    g.slots[slot].
	    logged_in ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
	pInfo->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;
	return CKR_OK;
}

static CK_RV
impl_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	   CK_UTF8CHAR * pPin, CK_ULONG ulPinLen)
{
	(void)userType;
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (g.slots[slot].logged_in)
		return CKR_USER_ALREADY_LOGGED_IN;

	/*
	 * Reject an empty PIN locally rather than sending "LOGIN " to the
	 * daemon. reliquary has no protected-authentication-path, so an empty
	 * PIN can never unwrap the token master key -- this is always a
	 * failed login. The daemon's LOGIN now raises NEEDPIN on an empty
	 * line (added for the scd-proxy's CHECKPIN->LOGIN relay path, which
	 * has a real inquire callback to answer it); this module's
	 * client_command_ok has no inquire callback, so guarding here keeps
	 * C_Login deterministic instead of depending on the daemon aborting
	 * that unanswerable inquiry back to BAD_PIN.
	 */
	if (!pPin || ulPinLen == 0)
		return CKR_PIN_INCORRECT;

	char cmd[512];
	char pin_buf[257];
	size_t plen =
	    ulPinLen < sizeof(pin_buf) - 1 ? ulPinLen : sizeof(pin_buf) - 1;
	if (pPin && plen > 0)
		memcpy(pin_buf, pPin, plen);
	pin_buf[plen] = '\0';

	snprintf(cmd, sizeof(cmd), "LOGIN %s", pin_buf);
	gpg_error_t err = client_command_ok(g.slots[slot].conn, cmd);
	if (err) {
		unsigned int ec = gpg_err_code(err);
		if (ec == GPG_ERR_BAD_PIN || ec == GPG_ERR_BAD_PASSPHRASE)
			return CKR_PIN_INCORRECT;
		if (ec == GPG_ERR_PIN_BLOCKED)
			return CKR_PIN_LOCKED;
		return CKR_GENERAL_ERROR;
	}

	g.slots[slot].logged_in = 1;
	return CKR_OK;
}

static CK_RV
impl_Logout(CK_SESSION_HANDLE hSession)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!g.slots[slot].logged_in)
		return CKR_USER_NOT_LOGGED_IN;

	client_command_ok(g.slots[slot].conn, "LOGOUT");
	g.slots[slot].logged_in = 0;
	return CKR_OK;
}

static CK_RV
impl_FindObjectsInit(CK_SESSION_HANDLE hSession,
		     CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;

	g.slots[slot].find_class = 0;	/* any */
	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue &&
		    pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
			g.slots[slot].find_class =
			    *(CK_OBJECT_CLASS *) pTemplate[i].pValue;
		}
	}

	g.slots[slot].find_active = 1;
	g.slots[slot].find_returned = 0;
	return CKR_OK;
}

static CK_RV
impl_FindObjects(CK_SESSION_HANDLE hSession,
		 CK_OBJECT_HANDLE * phObject,
		 CK_ULONG ulMaxObjectCount, CK_ULONG * pulObjectCount)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!g.slots[slot].find_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	CK_ULONG count = 0;
	int idx = 0;		/* tracks position across all key slots */

	for (int kslot = 0; kslot < 3; kslot++) {
		if (!g.slots[slot].algorithm[kslot][0])
			continue;	/* empty slot */

		if (count < ulMaxObjectCount
		    && idx >= g.slots[slot].find_returned
		    && (g.slots[slot].find_class == 0
			|| g.slots[slot].find_class == CKO_PRIVATE_KEY)) {
			phObject[count++] = OBJ_HANDLE(slot, kslot, 1);
		}
		idx++;

		if (count < ulMaxObjectCount
		    && idx >= g.slots[slot].find_returned
		    && (g.slots[slot].find_class == 0
			|| g.slots[slot].find_class == CKO_PUBLIC_KEY)) {
			phObject[count++] = OBJ_HANDLE(slot, kslot, 0);
		}
		idx++;
	}

	g.slots[slot].find_returned = idx;	/* all offered */
	*pulObjectCount = count;
	return CKR_OK;
}

static CK_RV
impl_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;

	g.slots[slot].find_active = 0;
	g.slots[slot].find_returned = 0;
	return CKR_OK;
}

static CK_RV
impl_GetAttributeValue(CK_SESSION_HANDLE hSession,
		       CK_OBJECT_HANDLE hObject,
		       CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	if (!g.slots[SESSION_TO_SLOT(hSession)].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pTemplate)
		return CKR_ARGUMENTS_BAD;

	/*
	 * Derived (ECDH) secret-key session objects: served from the slot's
	 * derived[] table rather than from an encoded token-key handle.
	 */
	if (IS_DERIVED_HANDLE(hObject)) {
		CK_SLOT_ID dslot = DERIVED_PSLOT(hObject);
		int didx = DERIVED_IDX(hObject);
		if (dslot >= g.num_slots || didx < 0 || didx >= MAX_DERIVED
		    || !g.slots[dslot].derived[didx].in_use)
			return CKR_OBJECT_HANDLE_INVALID;

		CK_OBJECT_CLASS scls = CKO_SECRET_KEY;
		CK_KEY_TYPE skt = CKK_GENERIC_SECRET;
		CK_BBOOL b_true = CK_TRUE;
		CK_BBOOL b_false = CK_FALSE;
		unsigned char *val = g.slots[dslot].derived[didx].value;
		CK_ULONG vlen = (CK_ULONG) g.slots[dslot].derived[didx].value_len;

		for (CK_ULONG i = 0; i < ulCount; i++) {
			CK_VOID_PTR src = NULL;
			CK_ULONG src_len = 0;
			switch (pTemplate[i].type) {
			case CKA_CLASS:
				src = &scls;
				src_len = sizeof(scls);
				break;
			case CKA_KEY_TYPE:
				src = &skt;
				src_len = sizeof(skt);
				break;
			case CKA_TOKEN:
			case CKA_SENSITIVE:
				src = &b_false;
				src_len = sizeof(CK_BBOOL);
				break;
			case CKA_PRIVATE:
			case CKA_EXTRACTABLE:
				src = &b_true;
				src_len = sizeof(CK_BBOOL);
				break;
			case CKA_VALUE:
				src = val;
				src_len = vlen;
				break;
			case CKA_VALUE_LEN:{
					static CK_ULONG vl;
					vl = vlen;
					src = &vl;
					src_len = sizeof(vl);
					break;
				}
			default:
				pTemplate[i].ulValueLen =
				    CK_UNAVAILABLE_INFORMATION;
				continue;
			}
			if (!pTemplate[i].pValue) {
				pTemplate[i].ulValueLen = src_len;
			} else if (pTemplate[i].ulValueLen >= src_len) {
				memcpy(pTemplate[i].pValue, src, src_len);
				pTemplate[i].ulValueLen = src_len;
			} else {
				pTemplate[i].ulValueLen =
				    CK_UNAVAILABLE_INFORMATION;
			}
		}
		return CKR_OK;
	}

	CK_SLOT_ID slot = OBJ_PSLOT(hObject);
	int kslot = OBJ_KSLOT(hObject);
	int is_priv = OBJ_IS_PRIV(hObject);

	/* Determine key type from algorithm */
	CK_KEY_TYPE kt = CKK_RSA;
	if (algo_is_ed25519(g.slots[slot].algorithm[kslot])) {
		kt = CKK_EC_EDWARDS;
	} else if (algo_is_ec(g.slots[slot].algorithm[kslot])) {
		kt = CKK_EC;
	}

	CK_OBJECT_CLASS cls = is_priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;

	/*
	 * Usage capabilities reflect the OpenPGP slot role (and algorithm),
	 * matching the daemon's per-slot mechanism policy -- not blanket-true
	 * for every private key.  Sign/auth slots sign; an RSA encrypt slot
	 * decrypts; an EC encrypt slot derives (ECDH).
	 */
	const char *kalgo = g.slots[slot].algorithm[kslot];
	CK_BBOOL can_sign = (is_priv && (kslot == RELIQUARY_SLOT_SIGN
					 || kslot == RELIQUARY_SLOT_AUTH))
	    ? CK_TRUE : CK_FALSE;
	CK_BBOOL can_decrypt = (is_priv && kslot == RELIQUARY_SLOT_ENCRYPT
				&& algo_is_rsa(kalgo)) ? CK_TRUE : CK_FALSE;
	CK_BBOOL can_derive = (is_priv && kslot == RELIQUARY_SLOT_ENCRYPT
			       && algo_is_ec(kalgo)
			       && !algo_is_ed25519(kalgo)) ? CK_TRUE : CK_FALSE;

	for (CK_ULONG i = 0; i < ulCount; i++) {
		CK_VOID_PTR src = NULL;
		CK_ULONG src_len = 0;

		switch (pTemplate[i].type) {
		case CKA_CLASS:
			src = &cls;
			src_len = sizeof(cls);
			break;
		case CKA_KEY_TYPE:
			src = &kt;
			src_len = sizeof(kt);
			break;
		case CKA_TOKEN:
			src = &ck_true;
			src_len = sizeof(ck_true);
			break;
		case CKA_PRIVATE:
			src = is_priv ? &ck_true : &ck_false;
			src_len = sizeof(CK_BBOOL);
			break;
		case CKA_SIGN:
			src = &can_sign;
			src_len = sizeof(CK_BBOOL);
			break;
		case CKA_DECRYPT:
			src = &can_decrypt;
			src_len = sizeof(CK_BBOOL);
			break;
		case CKA_DERIVE:
			src = &can_derive;
			src_len = sizeof(CK_BBOOL);
			break;
		case CKA_LABEL:
			src = g.slots[slot].label;
			src_len = (CK_ULONG) strlen(g.slots[slot].label);
			break;
		case CKA_ID:{
				/* Use slot index as a single-byte ID */
				static CK_BYTE id_byte;
				id_byte = (CK_BYTE) slot;
				src = &id_byte;
				src_len = 1;
				break;
			}
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
		case CKA_EC_POINT:{
				unsigned char *raw = g.slots[slot].pubkey_raw[kslot];
				size_t rlen = g.slots[slot].pubkey_raw_len[kslot];
				unsigned char *comp = NULL;
				size_t comp_len = 0;
				if (!raw)
					goto unavail;
				if (pTemplate[i].type == CKA_MODULUS)
					comp = sexp_extract_mpi(raw, rlen,
								"rsa", "n",
								&comp_len);
				else if (pTemplate[i].type ==
					 CKA_PUBLIC_EXPONENT)
					comp = sexp_extract_mpi(raw, rlen,
								"rsa", "e",
								&comp_len);
				else {
					/* CKA_EC_POINT: DER OCTET STRING wrapping raw point */
					unsigned char *pt = NULL;
					size_t pt_len = 0;
					pt = sexp_extract_raw(raw, rlen,
							      "ecc", "q",
							      &pt_len);
					if (!pt)
						goto unavail;
					/*
					 * Ed25519: imported keys store q as
					 * 0x40 || 32-byte point (gcrypt
					 * convention, see sshkey.c);
					 * OpenSSH's PKCS#11 EdDSA reader
					 * wants the bare 32-byte point.
					 * Strip the prefix so we emit
					 * 04 20 || <32 bytes>.
					 */
					unsigned char *q = pt;
					size_t qlen = pt_len;
					if (algo_is_ed25519
					    (g.slots[slot].algorithm[kslot])
					    && qlen == 33 && q[0] == 0x40) {
						q++;
						qlen--;
					}
					/* DER: 0x04 (OCTET STRING) + length + data */
					size_t der_len;
					if (qlen < 128)
						der_len = 2 + qlen;
					else
						der_len = 3 + qlen;
					comp = malloc(der_len);
					if (!comp) {
						free(pt);
						goto unavail;
					}
					comp[0] = 0x04;	/* OCTET STRING tag */
					if (qlen < 128) {
						comp[1] = (unsigned char)qlen;
						memcpy(comp + 2, q, qlen);
					} else {
						comp[1] = 0x81;
						comp[2] = (unsigned char)qlen;
						memcpy(comp + 3, q, qlen);
					}
					comp_len = der_len;
					free(pt);
				}
				if (!comp)
					goto unavail;
				if (!pTemplate[i].pValue) {
					pTemplate[i].ulValueLen = comp_len;
				} else if (pTemplate[i].ulValueLen >= comp_len) {
					memcpy(pTemplate[i].pValue, comp,
					       comp_len);
					pTemplate[i].ulValueLen = comp_len;
				} else {
					/* Buffer too small -- report needed size */
					pTemplate[i].ulValueLen = comp_len;
				}
				free(comp);
				continue;
			}
		case CKA_EC_PARAMS:{
				/* DER-encoded OID for the curve */
				static const unsigned char oid_p256[] =
				    { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
					0x3d, 0x03, 0x01, 0x07
				};
				static const unsigned char oid_p384[] =
				    { 0x06, 0x05, 0x2b, 0x81, 0x04,
					0x00, 0x22
				};
				static const unsigned char oid_p521[] =
				    { 0x06, 0x05, 0x2b, 0x81, 0x04,
					0x00, 0x23
				};
				static const unsigned char oid_ed25519[] =
				    { 0x06, 0x03, 0x2b, 0x65, 0x70 };
				const char *a = g.slots[slot].algorithm[kslot];
				if (algo_is_ed25519(a)) {
					src = (CK_VOID_PTR) oid_ed25519;
					src_len = sizeof(oid_ed25519);
				} else if (strstr(a, "p256") || strstr(a, "P-256")) {
					src = (CK_VOID_PTR) oid_p256;
					src_len = sizeof(oid_p256);
				} else if (strstr(a, "p384")
					   || strstr(a, "P-384")) {
					src = (CK_VOID_PTR) oid_p384;
					src_len = sizeof(oid_p384);
				} else if (strstr(a, "p521")
					   || strstr(a, "P-521")) {
					src = (CK_VOID_PTR) oid_p521;
					src_len = sizeof(oid_p521);
				} else {
					goto unavail;
				}
				break;
			}
		default:
 unavail:
			pTemplate[i].ulValueLen = 0;
			continue;
		}

		if (!pTemplate[i].pValue) {
			pTemplate[i].ulValueLen = src_len;
		} else if (pTemplate[i].ulValueLen >= src_len) {
			memcpy(pTemplate[i].pValue, src, src_len);
			pTemplate[i].ulValueLen = src_len;
		} else {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		}
	}

	return CKR_OK;
}

static CK_RV
impl_SignInit(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM * pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pMechanism)
		return CKR_ARGUMENTS_BAD;
	if (!wire_mech(0, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_PSS
	    && pMechanism->pParameter) {
		CK_RSA_PKCS_PSS_PARAMS *p = pMechanism->pParameter;
		if (p->hashAlg != CKM_SHA256 || p->mgf != CKG_MGF1_SHA256)
			return CKR_MECHANISM_PARAM_INVALID;
	}

	g.slots[slot].pending_op = 1;
	g.slots[slot].pending_mech = pMechanism->mechanism;
	g.slots[slot].pending_kslot = OBJ_KSLOT(hKey);
	return CKR_OK;
}

static CK_RV
impl_Sign(CK_SESSION_HANDLE hSession,
	  CK_BYTE * pData, CK_ULONG ulDataLen,
	  CK_BYTE * pSignature, CK_ULONG * pulSignatureLen)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (g.slots[slot].pending_op != 1)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	/* Size query: return estimated signature length */
	if (!pSignature) {
		/* Conservative estimate: RSA up to 512 bytes, EC up to 132 */
		if (algo_is_ec(g.slots[slot].algorithm[g.slots[slot].pending_kslot])) {
			*pulSignatureLen = 132;
		} else {
			*pulSignatureLen = 512;
		}
		/* Do NOT clear pending_op on size query */
		return CKR_OK;
	}

	const char *mn = wire_mech(0, g.slots[slot].pending_mech);
	int kslot = g.slots[slot].pending_kslot;
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "SIGN %d %s", kslot, mn);

	/*
	 * Input data travels out-of-band via INQUIRE, raw binary -- not hex
	 * on the command line, which could truncate for large inputs.
	 */
	unsigned char *sig = NULL;
	size_t sig_len = 0;
	gpg_error_t err = client_command_data_reply(g.slots[slot].conn, cmd,
						    pData, ulDataLen,
						    &sig, &sig_len);
	if (err) {
		free(sig);
		g.slots[slot].pending_op = 0;
		return CKR_GENERAL_ERROR;
	}

	if (sig_len > *pulSignatureLen) {
		free(sig);
		g.slots[slot].pending_op = 0;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pSignature, sig, sig_len);
	free(sig);

	*pulSignatureLen = (CK_ULONG) sig_len;
	g.slots[slot].pending_op = 0;
	return CKR_OK;
}

static CK_RV
impl_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE * pPart, CK_ULONG ulPartLen)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (g.slots[slot].pending_op != 1)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t need = g.slots[slot].sign_buf_len + ulPartLen;
	if (need > g.slots[slot].sign_buf_cap) {
		size_t cap = need * 2 + 64;
		unsigned char *tmp = realloc(g.slots[slot].sign_buf, cap);
		if (!tmp)
			return CKR_GENERAL_ERROR;
		g.slots[slot].sign_buf = tmp;
		g.slots[slot].sign_buf_cap = cap;
	}
	memcpy(g.slots[slot].sign_buf + g.slots[slot].sign_buf_len, pPart,
	       ulPartLen);
	g.slots[slot].sign_buf_len += ulPartLen;
	return CKR_OK;
}

static CK_RV
impl_SignFinal(CK_SESSION_HANDLE hSession,
	       CK_BYTE * pSignature, CK_ULONG * pulSignatureLen)
{
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	/* Delegate to impl_Sign with the accumulated buffer */
	CK_RV rv = impl_Sign(hSession, g.slots[slot].sign_buf,
			     (CK_ULONG) g.slots[slot].sign_buf_len,
			     pSignature, pulSignatureLen);
	/* Only free the buffer when the operation is complete (not on size query) */
	if (pSignature || rv != CKR_OK) {
		free(g.slots[slot].sign_buf);
		g.slots[slot].sign_buf = NULL;
		g.slots[slot].sign_buf_len = 0;
		g.slots[slot].sign_buf_cap = 0;
	}
	return rv;
}

static CK_RV
impl_DecryptInit(CK_SESSION_HANDLE hSession,
		 CK_MECHANISM * pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pMechanism)
		return CKR_ARGUMENTS_BAD;
	if (!wire_mech(1, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_OAEP
	    && pMechanism->pParameter) {
		CK_RSA_PKCS_OAEP_PARAMS *p = pMechanism->pParameter;
		if (p->hashAlg != CKM_SHA256 || p->mgf != CKG_MGF1_SHA256)
			return CKR_MECHANISM_PARAM_INVALID;
	}

	g.slots[slot].pending_op = 2;
	g.slots[slot].pending_mech = pMechanism->mechanism;
	g.slots[slot].pending_kslot = OBJ_KSLOT(hKey);
	return CKR_OK;
}

static CK_RV
impl_Decrypt(CK_SESSION_HANDLE hSession,
	     CK_BYTE * pEncryptedData, CK_ULONG ulEncryptedDataLen,
	     CK_BYTE * pData, CK_ULONG * pulDataLen)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (g.slots[slot].pending_op != 2)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!pulDataLen)
		return CKR_ARGUMENTS_BAD;

	const char *mn = wire_mech(1, g.slots[slot].pending_mech);
	int kslot = g.slots[slot].pending_kslot;
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "DECRYPT %d %s", kslot, mn);

	/*
	 * Ciphertext travels out-of-band via INQUIRE, raw binary -- not hex
	 * on the command line, which truncates for e.g. an rsa4096 (512-byte /
	 * 1024-hex-char) ciphertext.
	 */
	unsigned char *pt = NULL;
	size_t pt_len = 0;
	gpg_error_t err = client_command_data_reply(g.slots[slot].conn, cmd,
						    pEncryptedData,
						    ulEncryptedDataLen,
						    &pt, &pt_len);
	if (err) {
		free(pt);
		g.slots[slot].pending_op = 0;
		return CKR_GENERAL_ERROR;
	}

	if (!pData) {
		/* size query */
		*pulDataLen = (CK_ULONG) pt_len;
		free(pt);
		return CKR_OK;
	}

	if (pt_len > *pulDataLen) {
		free(pt);
		g.slots[slot].pending_op = 0;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(pData, pt, pt_len);
	free(pt);

	*pulDataLen = (CK_ULONG) pt_len;
	g.slots[slot].pending_op = 0;
	return CKR_OK;
}

/*
 * C_DeriveKey: ECDH (CKM_ECDH1_DERIVE).  Wraps the peer EC point from the
 * mechanism parameter into the gcrypt public-key S-expression the daemon's
 * DERIVE consumes, streams it out-of-band via INQUIRE over the same session
 * transport the sign / decrypt paths use, and materializes the returned
 * shared secret as a CKO_SECRET_KEY session object in the slot's derived[]
 * table.
 */
static CK_RV
impl_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM * pMechanism,
	       CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE * pTemplate,
	       CK_ULONG ulCount, CK_OBJECT_HANDLE * phKey)
{
	if (!g.initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!SESSION_VALID(hSession))
		return CKR_SESSION_HANDLE_INVALID;
	CK_SLOT_ID slot = SESSION_TO_SLOT(hSession);
	if (!g.slots[slot].session_open)
		return CKR_SESSION_HANDLE_INVALID;
	if (!pMechanism || !phKey)
		return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_ECDH1_DERIVE)
		return CKR_MECHANISM_INVALID;

	/* The base key must be an EC (nistp) private key on this token. */
	int kslot = OBJ_KSLOT(hBaseKey);
	if (kslot < 0 || kslot >= 3)
		return CKR_KEY_HANDLE_INVALID;
	const char *algo = g.slots[slot].algorithm[kslot];
	const char *curve;
	if (algo && strncmp(algo, "nistp256", 8) == 0)
		curve = "NIST P-256";
	else if (algo && strncmp(algo, "nistp384", 8) == 0)
		curve = "NIST P-384";
	else if (algo && strncmp(algo, "nistp521", 8) == 0)
		curve = "NIST P-521";
	else
		return CKR_KEY_TYPE_INCONSISTENT;

	/* Mechanism parameter carries the peer EC point (CKD_NULL only). */
	if (!pMechanism->pParameter
	    || pMechanism->ulParameterLen < sizeof(CK_ECDH1_DERIVE_PARAMS))
		return CKR_MECHANISM_PARAM_INVALID;
	CK_ECDH1_DERIVE_PARAMS *p = pMechanism->pParameter;
	if (p->kdf != CKD_NULL)
		return CKR_MECHANISM_PARAM_INVALID;
	if (!p->pPublicData || p->ulPublicDataLen == 0)
		return CKR_MECHANISM_PARAM_INVALID;

	/*
	 * Wrap the raw peer point into the canonical gcrypt public-key sexp the
	 * daemon parses.  The PKCS#11 peer point is the uncompressed octet
	 * string, which gcrypt accepts verbatim as q.
	 */
	gcry_sexp_t peer = NULL;
	if (gcry_sexp_build(&peer, NULL, "(public-key(ecc(curve %s)(q %b)))",
			    curve, (int)p->ulPublicDataLen,
			    p->pPublicData) != 0)
		return CKR_MECHANISM_PARAM_INVALID;
	size_t canon_len = gcry_sexp_sprint(peer, GCRYSEXP_FMT_CANON, NULL, 0);
	if (canon_len == 0) {
		gcry_sexp_release(peer);
		return CKR_FUNCTION_FAILED;
	}
	unsigned char *canon = malloc(canon_len);
	if (!canon) {
		gcry_sexp_release(peer);
		return CKR_HOST_MEMORY;
	}
	gcry_sexp_sprint(peer, GCRYSEXP_FMT_CANON, canon, canon_len);
	gcry_sexp_release(peer);

	char cmd[64];
	snprintf(cmd, sizeof(cmd), "DERIVE %d derive.ecdh", kslot);

	/*
	 * Peer EC point travels out-of-band via INQUIRE, raw binary -- not
	 * hex on the command line, mirroring impl_Sign/impl_Decrypt.
	 */
	unsigned char *secret = NULL;
	size_t secret_len = 0;
	gpg_error_t err = client_command_data_reply(g.slots[slot].conn, cmd,
						    canon, canon_len,
						    &secret, &secret_len);
	free(canon);
	if (err) {
		free(secret);
		return CKR_FUNCTION_FAILED;
	}
	if (secret_len == 0) {
		free(secret);
		return CKR_FUNCTION_FAILED;
	}

	/*
	 * Honor CKA_VALUE_LEN: for CKD_NULL the leading bytes of the shared
	 * secret are taken.  A request longer than the secret is inconsistent.
	 */
	CK_ULONG want_len = 0;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_VALUE_LEN && pTemplate[i].pValue
		    && pTemplate[i].ulValueLen == sizeof(CK_ULONG))
			want_len = *(CK_ULONG *) pTemplate[i].pValue;
	}
	if (want_len > secret_len) {
		free(secret);
		return CKR_TEMPLATE_INCONSISTENT;
	}
	if (want_len > 0)
		secret_len = want_len;

	/* Materialize a session secret-key object in the slot's derived table. */
	int idx = -1;
	for (int i = 0; i < MAX_DERIVED; i++) {
		if (!g.slots[slot].derived[i].in_use) {
			idx = i;
			break;
		}
	}
	if (idx < 0) {
		free(secret);
		return CKR_HOST_MEMORY;
	}
	g.slots[slot].derived[idx].value = secret;
	g.slots[slot].derived[idx].value_len = secret_len;
	g.slots[slot].derived[idx].in_use = 1;

	*phKey = DERIVED_HANDLE(slot, idx);
	return CKR_OK;
}

/* ---------- function list ---------- */

static CK_FUNCTION_LIST function_list = {
	.version = {3, 0},
	.C_Initialize = impl_Initialize,
	.C_Finalize = impl_Finalize,
	.C_GetInfo = impl_GetInfo,
	.C_GetFunctionList = STUB(CK_C_GetFunctionList),
	.C_GetSlotList = impl_GetSlotList,
	.C_GetSlotInfo = impl_GetSlotInfo,
	.C_GetTokenInfo = impl_GetTokenInfo,
	.C_GetMechanismList = impl_GetMechanismList,
	.C_GetMechanismInfo = impl_GetMechanismInfo,
	.C_InitToken = STUB(CK_C_InitToken),
	.C_InitPIN = STUB(CK_C_InitPIN),
	.C_SetPIN = STUB(CK_C_SetPIN),
	.C_OpenSession = impl_OpenSession,
	.C_CloseSession = impl_CloseSession,
	.C_CloseAllSessions = impl_CloseAllSessions,
	.C_GetSessionInfo = impl_GetSessionInfo,
	.C_GetOperationState = STUB(CK_C_GetOperationState),
	.C_SetOperationState = STUB(CK_C_SetOperationState),
	.C_Login = impl_Login,
	.C_Logout = impl_Logout,
	.C_CreateObject = STUB(CK_C_CreateObject),
	.C_CopyObject = STUB(CK_C_CopyObject),
	.C_DestroyObject = STUB(CK_C_DestroyObject),
	.C_GetObjectSize = STUB(CK_C_GetObjectSize),
	.C_GetAttributeValue = impl_GetAttributeValue,
	.C_SetAttributeValue = STUB(CK_C_SetAttributeValue),
	.C_FindObjectsInit = impl_FindObjectsInit,
	.C_FindObjects = impl_FindObjects,
	.C_FindObjectsFinal = impl_FindObjectsFinal,
	.C_EncryptInit = STUB(CK_C_EncryptInit),
	.C_Encrypt = STUB(CK_C_Encrypt),
	.C_EncryptUpdate = STUB(CK_C_EncryptUpdate),
	.C_EncryptFinal = STUB(CK_C_EncryptFinal),
	.C_DecryptInit = (CK_C_DecryptInit) impl_DecryptInit,
	.C_Decrypt = (CK_C_Decrypt) impl_Decrypt,
	.C_DecryptUpdate = STUB(CK_C_DecryptUpdate),
	.C_DecryptFinal = STUB(CK_C_DecryptFinal),
	.C_DigestInit = STUB(CK_C_DigestInit),
	.C_Digest = STUB(CK_C_Digest),
	.C_DigestUpdate = STUB(CK_C_DigestUpdate),
	.C_DigestKey = STUB(CK_C_DigestKey),
	.C_DigestFinal = STUB(CK_C_DigestFinal),
	.C_SignInit = (CK_C_SignInit) impl_SignInit,
	.C_Sign = (CK_C_Sign) impl_Sign,
	.C_SignUpdate = (CK_C_SignUpdate) impl_SignUpdate,
	.C_SignFinal = (CK_C_SignFinal) impl_SignFinal,
	.C_SignRecoverInit = STUB(CK_C_SignRecoverInit),
	.C_SignRecover = STUB(CK_C_SignRecover),
	.C_VerifyInit = STUB(CK_C_VerifyInit),
	.C_Verify = STUB(CK_C_Verify),
	.C_VerifyUpdate = STUB(CK_C_VerifyUpdate),
	.C_VerifyFinal = STUB(CK_C_VerifyFinal),
	.C_VerifyRecoverInit = STUB(CK_C_VerifyRecoverInit),
	.C_VerifyRecover = STUB(CK_C_VerifyRecover),
	.C_DigestEncryptUpdate = STUB(CK_C_DigestEncryptUpdate),
	.C_DecryptDigestUpdate = STUB(CK_C_DecryptDigestUpdate),
	.C_SignEncryptUpdate = STUB(CK_C_SignEncryptUpdate),
	.C_DecryptVerifyUpdate = STUB(CK_C_DecryptVerifyUpdate),
	.C_GenerateKey = STUB(CK_C_GenerateKey),
	.C_GenerateKeyPair = STUB(CK_C_GenerateKeyPair),
	.C_WrapKey = STUB(CK_C_WrapKey),
	.C_UnwrapKey = STUB(CK_C_UnwrapKey),
	.C_DeriveKey = impl_DeriveKey,
	.C_SeedRandom = STUB(CK_C_SeedRandom),
	.C_GenerateRandom = STUB(CK_C_GenerateRandom),
	.C_GetFunctionStatus = STUB(CK_C_GetFunctionStatus),
	.C_CancelFunction = STUB(CK_C_CancelFunction),
	.C_WaitForSlotEvent = STUB(CK_C_WaitForSlotEvent),
};

/* ---------- exported entry point ---------- */

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &function_list;
	return CKR_OK;
}
