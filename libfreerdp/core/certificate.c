/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Certificate Handling
 *
 * Copyright 2011 Jiten Pathy
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <winpr/assert.h>
#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/file.h>
#include <winpr/crypto.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "certificate.h"
#include "../crypto/crypto.h"
#include "../crypto/opensslcompat.h"

#define TAG "com.freerdp.core"

#define TSSK_KEY_LENGTH 64

/**
 *
 * X.509 Certificate Structure
 *
 * Certificate ::= SEQUENCE
 * {
 * 	tbsCertificate			TBSCertificate,
 * 	signatureAlgorithm		AlgorithmIdentifier,
 * 	signatureValue			BIT_STRING
 * }
 *
 * TBSCertificate ::= SEQUENCE
 * {
 * 	version			[0]	EXPLICIT Version DEFAULT v1,
 * 	serialNumber			CertificateSerialNumber,
 * 	signature			AlgorithmIdentifier,
 * 	issuer				Name,
 * 	validity			Validity,
 * 	subject				Name,
 * 	subjectPublicKeyInfo		SubjectPublicKeyInfo,
 * 	issuerUniqueID		[1]	IMPLICIT UniqueIdentifier OPTIONAL,
 * 	subjectUniqueId		[2]	IMPLICIT UniqueIdentifier OPTIONAL,
 * 	extensions		[3]	EXPLICIT Extensions OPTIONAL
 * }
 *
 * Version ::= INTEGER { v1(0), v2(1), v3(2) }
 *
 * CertificateSerialNumber ::= INTEGER
 *
 * AlgorithmIdentifier ::= SEQUENCE
 * {
 * 	algorithm			OBJECT_IDENTIFIER,
 * 	parameters			ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * Name ::= CHOICE { RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 *
 * AttributeTypeAndValue ::= SEQUENCE
 * {
 * 	type				AttributeType,
 * 	value				AttributeValue
 * }
 *
 * AttributeType ::= OBJECT_IDENTIFIER
 *
 * AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * Validity ::= SEQUENCE
 * {
 * 	notBefore			Time,
 * 	notAfter			Time
 * }
 *
 * Time ::= CHOICE
 * {
 * 	utcTime				UTCTime,
 * 	generalTime			GeneralizedTime
 * }
 *
 * UniqueIdentifier ::= BIT_STRING
 *
 * SubjectPublicKeyInfo ::= SEQUENCE
 * {
 * 	algorithm			AlgorithmIdentifier,
 * 	subjectPublicKey		BIT_STRING
 * }
 *
 * RSAPublicKey ::= SEQUENCE
 * {
 * 	modulus				INTEGER
 * 	publicExponent			INTEGER
 * }
 *
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 *
 * Extension ::= SEQUENCE
 * {
 * 	extnID				OBJECT_IDENTIFIER
 * 	critical			BOOLEAN DEFAULT FALSE,
 * 	extnValue			OCTET_STRING
 * }
 *
 */

struct rdp_CertBlob
{
	BIO* membio;
	X509* x509;

	BOOL isRSA;
	rdpCertInfo info;
};
typedef struct rdp_CertBlob rdpCertBlob;

struct rdp_certificate
{
	UINT32 count;
	rdpCertBlob* array;
};

struct rdp_rsa_key
{
	char* pem;
	size_t pem_length;

	BOOL isRSA;

	rdpCertInfo cert;
	BYTE* PrivateExponent;
	DWORD PrivateExponentLength;
};

static const char rsa_magic[4] = "RSA1";

static const char* certificate_read_errors[] = { "Certificate tag",
	                                             "TBSCertificate",
	                                             "Explicit Contextual Tag [0]",
	                                             "version",
	                                             "CertificateSerialNumber",
	                                             "AlgorithmIdentifier",
	                                             "Issuer Name",
	                                             "Validity",
	                                             "Subject Name",
	                                             "SubjectPublicKeyInfo Tag",
	                                             "subjectPublicKeyInfo::AlgorithmIdentifier",
	                                             "subjectPublicKeyInfo::subjectPublicKey",
	                                             "RSAPublicKey Tag",
	                                             "modulusLength",
	                                             "zero padding",
	                                             "modulusLength",
	                                             "modulus",
	                                             "publicExponent length",
	                                             "publicExponent" };

static const BYTE initial_signature[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
};

/*
 * Terminal Services Signing Keys.
 * Yes, Terminal Services Private Key is publicly available.
 */

static BYTE tssk_modulus[] = { 0x3d, 0x3a, 0x5e, 0xbd, 0x72, 0x43, 0x3e, 0xc9, 0x4d, 0xbb, 0xc1,
	                           0x1e, 0x4a, 0xba, 0x5f, 0xcb, 0x3e, 0x88, 0x20, 0x87, 0xef, 0xf5,
	                           0xc1, 0xe2, 0xd7, 0xb7, 0x6b, 0x9a, 0xf2, 0x52, 0x45, 0x95, 0xce,
	                           0x63, 0x65, 0x6b, 0x58, 0x3a, 0xfe, 0xef, 0x7c, 0xe7, 0xbf, 0xfe,
	                           0x3d, 0xf6, 0x5c, 0x7d, 0x6c, 0x5e, 0x06, 0x09, 0x1a, 0xf5, 0x61,
	                           0xbb, 0x20, 0x93, 0x09, 0x5f, 0x05, 0x6d, 0xea, 0x87 };

static BYTE tssk_privateExponent[] = {
	0x87, 0xa7, 0x19, 0x32, 0xda, 0x11, 0x87, 0x55, 0x58, 0x00, 0x16, 0x16, 0x25, 0x65, 0x68, 0xf8,
	0x24, 0x3e, 0xe6, 0xfa, 0xe9, 0x67, 0x49, 0x94, 0xcf, 0x92, 0xcc, 0x33, 0x99, 0xe8, 0x08, 0x60,
	0x17, 0x9a, 0x12, 0x9f, 0x24, 0xdd, 0xb1, 0x24, 0x99, 0xc7, 0x3a, 0xb8, 0x0a, 0x7b, 0x0d, 0xdd,
	0x35, 0x07, 0x79, 0x17, 0x0b, 0x51, 0x9b, 0xb3, 0xc7, 0x10, 0x01, 0x13, 0xe7, 0x3f, 0xf3, 0x5f
};

static const rdpRsaKey tssk = { .PrivateExponent = tssk_privateExponent,
	                            .PrivateExponentLength = sizeof(tssk_privateExponent),
	                            .cert = { .Modulus = tssk_modulus,
	                                      .ModulusLength = sizeof(tssk_modulus) } };

#if defined(CERT_VALIDATE_RSA)
static const BYTE tssk_exponent[] = { 0x5b, 0x7b, 0x88, 0xc0 };
#endif

static BOOL cert_clone_int(rdpCertificate* dst, const rdpCertificate* src);

static BOOL cert_info_create(rdpCertInfo* dst, const BIGNUM* rsa, const BIGNUM* rsa_e);
static BOOL cert_info_allocate(rdpCertInfo* info, size_t size);
static void cert_info_free(rdpCertInfo* info);
static BOOL cert_info_read_modulus(rdpCertInfo* info, size_t size, wStream* s);
static BOOL cert_info_read_exponent(rdpCertInfo* info, size_t size, wStream* s);
static void certificate_free_x509_certificate_chain(rdpCertificate* cert);

static BOOL cert_info_copy(rdpCertInfo* dst, const rdpCertInfo* src)
{
	WINPR_ASSERT(dst);
	WINPR_ASSERT(src);

	cert_info_free(dst);
	*dst = *src;

	if (src->ModulusLength > 0)
	{
		dst->Modulus = malloc(src->ModulusLength);
		if (!dst->Modulus)
			return FALSE;
		memcpy(dst->Modulus, src->Modulus, src->ModulusLength);
	}
	return TRUE;
}

/* [MS-RDPBCGR] 5.3.3.2 X.509 Certificate Chains:
 *
 * More detail[MS-RDPELE] section 2.2.1.4.2.
 */
static BOOL cert_blob_copy(rdpCertBlob* dst, const rdpCertBlob* src);
static void cert_blob_free(rdpCertBlob* blob, BOOL freemembuffer);
static BOOL cert_blob_write(const rdpCertBlob* blob, wStream* s);
static BOOL cert_blob_read(rdpCertBlob* blob, wStream* s);
static BOOL cert_blob_from_pem(rdpCertBlob* blob, const char* pem, size_t length);

static BOOL cert_update_rsa_from_x509(rdpCertBlob* blob)
{
	BOOL rc = TRUE;
	WINPR_ASSERT(blob);
	WINPR_ASSERT(blob->x509);

	blob->isRSA = FALSE;
	EVP_PKEY* pubkey = X509_get_pubkey(blob->x509);
	if (pubkey)
	{
		RSA* rsa = EVP_PKEY_get1_RSA(pubkey);
		EVP_PKEY_free(pubkey);
		if (rsa)
		{
			const BIGNUM* rsa_e = NULL;
			const BIGNUM* rsa_n = NULL;
			RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
			if (!rsa_n || !rsa_e)
				rc = FALSE;
			else
			{
				if (!cert_info_create(&blob->info, rsa_n, rsa_e))
					rc = FALSE;
			}
			RSA_free(rsa);
			blob->isRSA = rc;
		}
	}
	return rc;
}

BOOL cert_blob_read(rdpCertBlob* blob, wStream* s)
{
	UINT32 certLength = 0;
	WINPR_ASSERT(blob);
	cert_blob_free(blob, FALSE);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;

	Stream_Read_UINT32(s, certLength);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, certLength))
		return FALSE;

	DEBUG_CERTIFICATE("X.509 Certificate #%" PRIu32 ", length:%" PRIu32 "", i + 1, certLength);

	const BYTE* data = Stream_Pointer(s);
	Stream_Seek(s, certLength);

	blob->x509 = d2i_X509(NULL, &data, certLength);
	if (!blob->x509)
		return FALSE;

	return cert_update_rsa_from_x509(blob);
}

BOOL cert_blob_write(const rdpCertBlob* blob, wStream* s)
{
	WINPR_ASSERT(blob);

	BYTE* data = NULL;
	const int len = i2d_X509(blob->x509, &data);
	if (len < 0)
		return FALSE;
	if (!Stream_EnsureRemainingCapacity(s, 4 + (size_t)len))
		return FALSE;

	Stream_Write_UINT32(s, (UINT32)len);
	Stream_Write(s, data, (size_t)len);
	return TRUE;
}

void cert_blob_free(rdpCertBlob* blob, BOOL freemembuffer)
{
	if (!blob)
		return;
	X509_free(blob->x509);
	blob->x509 = NULL;

	if (freemembuffer)
	{
		BIO_free(blob->membio);
		blob->membio = NULL;
	}

	cert_info_free(&blob->info);
}

static BOOL cert_blob_init(rdpCertBlob* blob)
{
	WINPR_ASSERT(blob);
	blob->membio = BIO_s_secmem();
	if (!blob->membio)
		return FALSE;
	return TRUE;
}

static BOOL certificate_resize_x509_certificate_chain(rdpCertificate* cert, UINT32 count)
{
	WINPR_ASSERT(cert);

	if (count == 0)
	{
		certificate_free_x509_certificate_chain(cert);
		return TRUE;
	}

	UINT32 oldCount = cert->count;
	if (oldCount > count)
	{
		for (UINT32 x = count; x < oldCount; x++)
		{
			cert_blob_free(&cert->array[x], TRUE);
		}
	}

	rdpCertBlob* tmp = winpr_aligned_recalloc(cert->array, count, sizeof(rdpCertBlob), 16);
	if (!tmp)
		return FALSE;
	cert->array = tmp;
	cert->count = count;

	if (oldCount < count)
	{
		for (UINT32 x = oldCount; x < count; x++)
		{
			cert_blob_init(&cert->array[x]);
		}
	}
	return TRUE;
}

static BOOL certificate_ensure_array_size(rdpCertificate* cert, UINT32 count)
{
	WINPR_ASSERT(cert);
	WINPR_ASSERT(count > 0);
	if (count <= cert->count)
		return TRUE;
	return certificate_resize_x509_certificate_chain(cert, count);
}

static const rdpCertBlob* cert_get_const_blob_at(const rdpCertificate* cert, UINT32 index)
{
	WINPR_ASSERT(cert);
	if (index >= cert->count)
		return NULL;
	return &cert->array[index];
}

static rdpCertBlob* cert_get_blob_at(rdpCertificate* cert, UINT32 index)
{
	WINPR_ASSERT(cert);
	if (index >= cert->count)
		return NULL;
	return &cert->array[index];
}

/**
 * Free X.509 Certificate Chain.
 * @param x509_cert_chain X.509 certificate chain to be freed
 */

void certificate_free_x509_certificate_chain(rdpCertificate* cert)
{
	if (!cert)
		return;

	if (cert->array)
	{
		for (UINT32 i = 0; i < cert->count; i++)
		{
			rdpCertBlob* element = &cert->array[i];
			cert_blob_free(element, TRUE);
		}
	}

	winpr_aligned_free(cert->array);
	cert->array = NULL;
	cert->count = 0;
}

static BOOL certificate_process_server_public_key(rdpCertBlob* blob, wStream* s, size_t length)
{
	char magic[sizeof(rsa_magic)] = { 0 };
	UINT32 keylen = 0;
	UINT32 bitlen = 0;
	UINT32 datalen = 0;
	BYTE* tmp = NULL;

	WINPR_ASSERT(blob);
	WINPR_ASSERT(s);

	const size_t start = Stream_GetPosition(s);
	if (!Stream_CheckAndLogRequiredLength(TAG, s, 20))
		return FALSE;

	Stream_Read(s, magic, sizeof(magic));

	if (memcmp(magic, rsa_magic, sizeof(magic)) != 0)
	{
		WLog_ERR(TAG, "magic error");
		return FALSE;
	}

	blob->isRSA = TRUE;

	Stream_Read_UINT32(s, keylen);
	Stream_Read_UINT32(s, bitlen);
	Stream_Read_UINT32(s, datalen);
	Stream_Read(s, blob->info.exponent, 4);

	if ((keylen <= 8) || (!Stream_CheckAndLogRequiredLength(TAG, s, keylen)))
		return FALSE;

	blob->info.ModulusLength = keylen - 8;
	tmp = realloc(blob->info.Modulus, blob->info.ModulusLength);

	if (!tmp)
		return FALSE;
	blob->info.Modulus = tmp;

	Stream_Read(s, blob->info.Modulus, blob->info.ModulusLength);
	Stream_Seek(s, 8); /* 8 bytes of zero padding */

	// TODO: certe X509

	const size_t end = Stream_GetPosition(s);
	if (end - start != length)
	{
		WLog_ERR(TAG, "Invalid certificate length, expected %" PRIuz ", but only read %" PRIuz,
		         length, end - start);
		return FALSE;
	}
	return TRUE;
}

static BOOL certificate_process_server_public_signature(rdpCertBlob* blob, const BYTE* sigdata,
                                                        size_t sigdatalen, wStream* s,
                                                        UINT32 siglen)
{
	WINPR_ASSERT(blob);
	WINPR_ASSERT(blob->isRSA);
#if defined(CERT_VALIDATE_PADDING) || defined(CERT_VALIDATE_RSA)
	size_t i, sum;
#endif
#if defined(CERT_VALIDATE_RSA)
	BYTE sig[TSSK_KEY_LENGTH];
#endif
	BYTE encsig[TSSK_KEY_LENGTH + 8];
#if defined(CERT_VALIDATE_MD5) && defined(CERT_VALIDATE_RSA)
	BYTE md5hash[WINPR_MD5_DIGEST_LENGTH];
#endif
#if !defined(CERT_VALIDATE_MD5) || !defined(CERT_VALIDATE_RSA)
	(void)sigdata;
	(void)sigdatalen;
#endif
	(void)blob;
	/* Do not bother with validation of server proprietary certificate. The use of MD5 here is not
	 * allowed under FIPS. Since the validation is not protecting against anything since the
	 * private/public keys are well known and documented in MS-RDPBCGR section 5.3.3.1, we are not
	 * gaining any security by using MD5 for signature comparison. Rather then use MD5
	 * here we just dont do the validation to avoid its use. Historically, freerdp has been ignoring
	 * a failed validation anyways. */
#if defined(CERT_VALIDATE_MD5)

	if (!winpr_Digest(WINPR_MD_MD5, sigdata, sigdatalen, md5hash, sizeof(md5hash)))
		return FALSE;

#endif
	Stream_Read(s, encsig, siglen);

	if (siglen < 8)
		return FALSE;

		/* Last 8 bytes shall be all zero. */
#if defined(CERT_VALIDATE_PADDING)

	for (sum = 0, i = sizeof(encsig) - 8; i < sizeof(encsig); i++)
		sum += encsig[i];

	if (sum != 0)
	{
		WLog_ERR(TAG, "invalid signature");
		return FALSE;
	}

#endif
#if defined(CERT_VALIDATE_RSA)

	if (crypto_rsa_public_decrypt(encsig, siglen - 8, TSSK_KEY_LENGTH, tssk_modulus, tssk_exponent,
	                              sig) <= 0)
	{
		WLog_ERR(TAG, "invalid RSA decrypt");
		return FALSE;
	}

	/* Verify signature. */
	/* Do not bother with validation of server proprietary certificate as described above. */
#if defined(CERT_VALIDATE_MD5)

	if (memcmp(md5hash, sig, sizeof(md5hash)) != 0)
	{
		WLog_ERR(TAG, "invalid signature");
		return FALSE;
	}

#endif
	/*
	 * Verify rest of decrypted data:
	 * The 17th byte is 0x00.
	 * The 18th through 62nd bytes are each 0xFF.
	 * The 63rd byte is 0x01.
	 */

	for (sum = 0, i = 17; i < 62; i++)
		sum += sig[i];

	if (sig[16] != 0x00 || sum != 0xFF * (62 - 17) || sig[62] != 0x01)
	{
		WLog_ERR(TAG, "invalid signature");
		return FALSE;
	}

#endif
	return TRUE;
}

static BOOL certificate_read_server_proprietary_certificate(rdpCertificate* certificate, wStream* s)
{
	UINT32 dwSigAlgId = 0;
	UINT32 dwKeyAlgId = 0;
	UINT16 wPublicKeyBlobType = 0;
	UINT16 wPublicKeyBlobLen = 0;
	UINT16 wSignatureBlobType = 0;
	UINT16 wSignatureBlobLen = 0;
	BYTE* sigdata = NULL;
	size_t sigdatalen = 0;

	WINPR_ASSERT(certificate);
	if (!certificate_ensure_array_size(certificate, 1))
		return FALSE;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 12))
		return FALSE;

	/* -4, because we need to include dwVersion */
	sigdata = Stream_Pointer(s) - 4;
	Stream_Read_UINT32(s, dwSigAlgId);
	Stream_Read_UINT32(s, dwKeyAlgId);

	if (!((dwSigAlgId == SIGNATURE_ALG_RSA) && (dwKeyAlgId == KEY_EXCHANGE_ALG_RSA)))
	{
		WLog_ERR(TAG,
		         "unsupported signature or key algorithm, dwSigAlgId=%" PRIu32
		         " dwKeyAlgId=%" PRIu32 "",
		         dwSigAlgId, dwKeyAlgId);
		return FALSE;
	}

	rdpCertBlob* blob = cert_get_blob_at(certificate, 0);
	WINPR_ASSERT(blob);

	blob->isRSA = TRUE;

	Stream_Read_UINT16(s, wPublicKeyBlobType);

	if (wPublicKeyBlobType != BB_RSA_KEY_BLOB)
	{
		WLog_ERR(TAG, "unsupported public key blob type %" PRIu16 "", wPublicKeyBlobType);
		return FALSE;
	}

	Stream_Read_UINT16(s, wPublicKeyBlobLen);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, wPublicKeyBlobLen))
		return FALSE;

	if (!certificate_process_server_public_key(blob, s, wPublicKeyBlobLen))
		return FALSE;

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;

	sigdatalen = Stream_Pointer(s) - sigdata;
	Stream_Read_UINT16(s, wSignatureBlobType);

	if (wSignatureBlobType != BB_RSA_SIGNATURE_BLOB)
	{
		WLog_ERR(TAG, "unsupported blob signature %" PRIu16 "", wSignatureBlobType);
		return FALSE;
	}

	Stream_Read_UINT16(s, wSignatureBlobLen);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, wSignatureBlobLen))
		return FALSE;

	if (wSignatureBlobLen != 72)
	{
		WLog_ERR(TAG, "invalid signature length (got %" PRIu16 ", expected 72)", wSignatureBlobLen);
		return FALSE;
	}

	if (!certificate_process_server_public_signature(blob, sigdata, sigdatalen, s,
	                                                 wSignatureBlobLen))
	{
		WLog_ERR(TAG, "unable to parse server public signature");
		return FALSE;
	}
	return TRUE;
}

/* [MS-RDPBCGR] 2.2.1.4.3.1.1.1 RSA Public Key (RSA_PUBLIC_KEY) */
static BOOL cert_write_rsa_public_key(wStream* s, const rdpCertBlob* blob)
{
	WINPR_ASSERT(blob);
	WINPR_ASSERT(blob->isRSA);

	const rdpCertInfo* info = &blob->info;

	const UINT32 keyLen = info->ModulusLength + 8;
	const UINT32 bitLen = info->ModulusLength * 8;
	const UINT32 dataLen = (bitLen / 8) - 1;
	const size_t pubExpLen = sizeof(info->exponent);
	const BYTE* pubExp = info->exponent;
	const BYTE* modulus = info->Modulus;

	const UINT16 wPublicKeyBlobLen = 16 + pubExpLen + keyLen;
	if (!Stream_EnsureRemainingCapacity(s, 2 + wPublicKeyBlobLen))
		return FALSE;
	Stream_Write_UINT16(s, wPublicKeyBlobLen);
	Stream_Write(s, rsa_magic, sizeof(rsa_magic));
	Stream_Write_UINT32(s, keyLen);
	Stream_Write_UINT32(s, bitLen);
	Stream_Write_UINT32(s, dataLen);
	Stream_Write(s, pubExp, pubExpLen);
	Stream_Write(s, modulus, info->ModulusLength);
	Stream_Zero(s, 8);
	return TRUE;
}

static BOOL cert_write_rsa_signature(wStream* s, const void* sigData, size_t sigDataLen)
{
	BYTE encryptedSignature[TSSK_KEY_LENGTH] = { 0 };
	BYTE signature[sizeof(initial_signature)] = { 0 };

	memcpy(signature, initial_signature, sizeof(initial_signature));
	if (!winpr_Digest(WINPR_MD_MD5, sigData, sigDataLen, signature, sizeof(signature)))
		return FALSE;

	crypto_rsa_private_encrypt(signature, sizeof(signature), &tssk, encryptedSignature,
	                           sizeof(encryptedSignature));

	if (!Stream_EnsureRemainingCapacity(s, 2 * sizeof(UINT16) + sizeof(encryptedSignature) + 8))
		return FALSE;
	Stream_Write_UINT16(s, BB_RSA_SIGNATURE_BLOB);
	Stream_Write_UINT16(s, sizeof(encryptedSignature) + 8); /* wSignatureBlobLen */
	Stream_Write(s, encryptedSignature, sizeof(encryptedSignature));
	Stream_Zero(s, 8);
	return TRUE;
}

/* [MS-RDPBCGR] 2.2.1.4.3.1.1 Server Proprietary Certificate (PROPRIETARYSERVERCERTIFICATE) */
static BOOL cert_write_server_certificate_v1(wStream* s, const rdpCertificate* certificate)
{
	const size_t start = Stream_GetPosition(s);
	const BYTE* sigData = Stream_Pointer(s) - sizeof(UINT32);

	WINPR_ASSERT(start >= 4);

	if (!Stream_EnsureRemainingCapacity(s, 10))
		return FALSE;
	Stream_Write_UINT32(s, SIGNATURE_ALG_RSA);
	Stream_Write_UINT32(s, KEY_EXCHANGE_ALG_RSA);
	Stream_Write_UINT16(s, BB_RSA_KEY_BLOB);
	if (!cert_write_rsa_public_key(s, certificate))
		return FALSE;

	const size_t end = Stream_GetPosition(s);
	return cert_write_rsa_signature(s, sigData, end - start + sizeof(UINT32));
}

static BOOL cert_write_server_certificate_v2(wStream* s, const rdpCertificate* certificate)
{
	WINPR_ASSERT(certificate);

	const size_t padding = 8ull + 4ull * certificate->count;

	if (Stream_EnsureRemainingCapacity(s, sizeof(UINT32)))
		return FALSE;

	Stream_Write_UINT32(s, certificate->count);
	for (UINT32 x = 0; x < certificate->count; x++)
	{
		const rdpCertBlob* cert = cert_get_const_blob_at(certificate, x);
		if (!cert_blob_write(cert, s))
			return FALSE;
	}

	if (Stream_EnsureRemainingCapacity(s, padding))
		return FALSE;
	Stream_Zero(s, padding);
	return FALSE;
}

SSIZE_T certificate_write_server_certificate(const rdpCertificate* certificate, UINT32 dwVersion,
                                             wStream* s)
{
	if (!certificate)
		return -1;

	const size_t start = Stream_GetPosition(s);
	if (!Stream_EnsureRemainingCapacity(s, 4))
		return -1;
	Stream_Write_UINT32(s, dwVersion);

	switch (dwVersion & CERT_CHAIN_VERSION_MASK)
	{
		case CERT_CHAIN_VERSION_1:
			if (!cert_write_server_certificate_v1(s, certificate))
				return -1;
			break;
		case CERT_CHAIN_VERSION_2:
			if (!cert_write_server_certificate_v2(s, certificate))
				return -1;
			break;
		default:
			WLog_ERR(TAG, "invalid certificate chain version:%" PRIu32 "",
			         dwVersion & CERT_CHAIN_VERSION_MASK);
			return -1;
	}

	const size_t end = Stream_GetPosition(s);
	return end - start;
}

/**
 * Read an X.509 Certificate Chain.
 * @param certificate certificate module
 * @param s stream
 */

static BOOL certificate_read_server_x509_certificate_chain(rdpCertificate* certificate, wStream* s)
{
	UINT32 numCertBlobs = 0;
	DEBUG_CERTIFICATE("Server X.509 Certificate Chain");

	WINPR_ASSERT(certificate);

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 4))
		return FALSE;

	Stream_Read_UINT32(s, numCertBlobs); /* numCertBlobs */
	if (!certificate_ensure_array_size(certificate, numCertBlobs))
		return FALSE;
	for (UINT32 i = 0; i < certificate->count; i++)
	{
		rdpCertBlob* blob = cert_get_blob_at(certificate, i);
		if (!cert_blob_read(blob, s))
			return FALSE;

		if (numCertBlobs - i == 1)
		{
		}

		if (blob->isRSA)
		{
			if ((numCertBlobs - i) == 2)
			{
				DEBUG_CERTIFICATE("License Server Certificate");
				DEBUG_LICENSE("modulus length:%" PRIu32 "", blob->info.ModulusLength);
			}
			else if (numCertBlobs - i == 1)
			{
				DEBUG_CERTIFICATE("Terminal Server Certificate");
				DEBUG_CERTIFICATE("modulus length:%" PRIu32 "",
				                  certificate->cert_info.ModulusLength);
			}
		}
	}
	return TRUE;
}

static BOOL certificate_write_server_x509_certificate_chain(const rdpCertificate* certificate,
                                                            wStream* s)
{
	UINT32 numCertBlobs = 0;

	WINPR_ASSERT(certificate);
	WINPR_ASSERT(s);

	numCertBlobs = certificate->count;

	if (!Stream_EnsureRemainingCapacity(s, 4))
		return FALSE;
	Stream_Write_UINT32(s, numCertBlobs); /* numCertBlobs */

	for (UINT32 i = 0; i < numCertBlobs; i++)
	{
		const rdpCertBlob* cert = &certificate->array[i];
		if (!cert_blob_write(cert, s))
			return FALSE;
	}

	return TRUE;
}

/**
 * Read a Server Certificate.
 * @param certificate certificate module
 * @param server_cert server certificate
 * @param length certificate length
 */

BOOL certificate_read_server_certificate(rdpCertificate* certificate, const BYTE* server_cert,
                                         size_t length)
{
	BOOL ret = FALSE;
	wStream *s, sbuffer;
	UINT32 dwVersion = 0;

	WINPR_ASSERT(certificate);

	if (length < 4) /* NULL certificate is not an error see #1795 */
		return TRUE;

	WINPR_ASSERT(server_cert);
	s = Stream_StaticConstInit(&sbuffer, server_cert, length);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	Stream_Read_UINT32(s, dwVersion); /* dwVersion (4 bytes) */

	switch (dwVersion & CERT_CHAIN_VERSION_MASK)
	{
		case CERT_CHAIN_VERSION_1:
			ret = certificate_read_server_proprietary_certificate(certificate, s);
			break;

		case CERT_CHAIN_VERSION_2:
			ret = certificate_read_server_x509_certificate_chain(certificate, s);
			break;

		default:
			WLog_ERR(TAG, "invalid certificate chain version:%" PRIu32 "",
			         dwVersion & CERT_CHAIN_VERSION_MASK);
			ret = FALSE;
			break;
	}

	return ret;
}

static BOOL read_bignum(BYTE** dst, UINT32* length, const BIGNUM* num, BOOL alloc)
{
	WINPR_ASSERT(dst);
	WINPR_ASSERT(length);
	WINPR_ASSERT(num);

	if (alloc)
	{
		*dst = NULL;
		*length = 0;
	}

	const int len = BN_num_bytes(num);
	if (len < 0)
		return FALSE;

	if (!alloc)
	{
		if (*length < (UINT32)len)
			return FALSE;
	}

	if (len > 0)
	{
		if (alloc)
		{
			*dst = malloc((size_t)len);
			if (!*dst)
				return FALSE;
		}
		BN_bn2bin(num, *dst);
		crypto_reverse(*dst, (size_t)len);
		*length = (UINT32)len;
	}

	return TRUE;
}

static BIO* bio_from_pem(const char* pem, size_t pem_length)
{
	if (!pem)
		return NULL;

	return BIO_new_mem_buf((const void*)pem, pem_length);
}

static RSA* rsa_from_private_pem(const char* pem, size_t pem_length)
{
	RSA* rsa = NULL;
	BIO* bio = bio_from_pem(pem, pem_length);
	if (!bio)
		return NULL;

	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	BIO_free_all(bio);
	return rsa;
}

static RSA* rsa_from_public_pem(const char* pem, size_t pem_length)
{
	RSA* rsa = NULL;
	BIO* bio = bio_from_pem(pem, pem_length);
	if (!bio)
		return NULL;

	rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
	BIO_free_all(bio);

	return rsa;
}

static BOOL key_read_private(rdpRsaKey* key, const char* pem, size_t pem_length)
{
	BOOL rc = FALSE;
	RSA* rsa = rsa_from_private_pem(pem, pem_length);
	if (!rsa)
		return TRUE;

	const BIGNUM* rsa_e = NULL;
	const BIGNUM* rsa_n = NULL;
	const BIGNUM* rsa_d = NULL;

	WINPR_ASSERT(key);
	if (!rsa)
	{
		WLog_ERR(TAG, "unable to load RSA key from PEM: %s", strerror(errno));
		goto fail;
	}

	switch (RSA_check_key(rsa))
	{
		case 0:
			WLog_ERR(TAG, "invalid RSA key in PEM");
			goto fail;

		case 1:
			/* Valid key. */
			break;

		default:
			WLog_ERR(TAG, "unexpected error when checking RSA key from: %s", strerror(errno));
			goto fail;
	}

	RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);

	if (BN_num_bytes(rsa_e) > 4)
	{
		WLog_ERR(TAG, "RSA public exponent in PEM too large");
		goto fail;
	}

	if (!read_bignum(&key->PrivateExponent, &key->PrivateExponentLength, rsa_d, TRUE))
		goto fail;

	if (!cert_info_create(&key->cert, rsa_n, rsa_e))
		goto fail;

	key->isRSA = TRUE;
	rc = TRUE;
fail:
	RSA_free(rsa);
	return rc;
}

static X509* x509_from_pem(const char* pem, size_t pem_length)
{
	X509* x509 = NULL;
	BIO* bio = bio_from_pem(pem, pem_length);
	if (!bio)
		return NULL;

	x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free_all(bio);
	return x509;
}

BOOL cert_blob_from_pem(rdpCertBlob* blob, const char* pem, size_t length)
{
	cert_blob_free(blob, FALSE);

	blob->x509 = x509_from_pem(pem, length);
	if (!blob->x509)
		return FALSE;
	return cert_update_rsa_from_x509(blob);
}

static BOOL cert_read_public(rdpCertificate* cert, const char* pem, size_t pem_length)
{
	BOOL rc = FALSE;
	X509* x509 = x509_from_pem(pem, pem_length);

	WINPR_ASSERT(cert);

	if (!x509)
	{
		WLog_ERR(TAG, "unable to load X509 from: %s", strerror(errno));
		goto fail;
	}

	rc = TRUE;
fail:
	X509_free(x509);
	return rc;
}

rdpRsaKey* freerdp_key_new_from_pem(const char* keycontent, size_t keycontent_length)
{
	rdpRsaKey* key = NULL;

	if (!keycontent || (keycontent_length == 0))
		return NULL;

	key = (rdpRsaKey*)calloc(1, sizeof(rdpRsaKey));

	if (!key)
		return NULL;

	key->pem = calloc(keycontent_length + 1, sizeof(char));
	if (!key->pem)
		goto fail;
	memcpy(key->pem, keycontent, keycontent_length);
	key->pem_length = keycontent_length;

	if (!key_read_private(key, keycontent, keycontent_length))
		goto fail;

	return key;
fail:
	freerdp_key_free(key);
	return NULL;
}

static char* read_pem_file(const char* name, size_t* plength)
{
	WINPR_ASSERT(name);
	WINPR_ASSERT(plength);

	*plength = 0;

	char* pem = NULL;
	SSIZE_T size = 0;
	FILE* fp = winpr_fopen(name, "rb");
	if (!fp)
	{
		WLog_ERR(TAG, "unable to open file %s: %s", name, strerror(errno));
		goto fail;
	}

	if (_fseeki64(fp, 0, SEEK_END) < 0)
	{
		WLog_ERR(TAG, "unable to seek in file %s: %s", name, strerror(errno));
		goto fail;
	}

	size = _ftelli64(fp);
	if (size < 0)
	{
		WLog_ERR(TAG, "unable to ftell in file %s: %s", name, strerror(errno));
		goto fail;
	}

	if (_fseeki64(fp, 0, SEEK_SET) < 0)
	{
		WLog_ERR(TAG, "unable to seek in file %s: %s", name, strerror(errno));
		goto fail;
	}

	pem = calloc((size_t)size + 1, sizeof(char));
	if (!pem)
	{
		WLog_ERR(TAG, "unable to allocate %" PRIdz " bytes", size);
		goto fail;
	}

	if (fread(pem, (size_t)size, 1, fp) != 1)
	{
		WLog_ERR(TAG, "unable to read from file %s: %s", name, strerror(errno));
		free(pem);
		pem = NULL;
		goto fail;
	}

	*plength = (size_t)size;
fail:
	return pem;
}

rdpRsaKey* freerdp_key_new_from_file(const char* keyfile)
{
	size_t length = 0;
	char* buffer = NULL;
	rdpRsaKey* key = NULL;

	if (!keyfile)
		return NULL;

	buffer = read_pem_file(keyfile, &length);
	if (!buffer)
		return NULL;
	key = freerdp_key_new_from_pem(buffer, length);
	free(buffer);
	return key;
}

rdpRsaKey* key_clone(const rdpRsaKey* key)
{
	if (!key)
		return NULL;

	rdpRsaKey* _key = (rdpRsaKey*)calloc(1, sizeof(rdpRsaKey));

	if (!_key)
		return NULL;

	*_key = *key;
	if (key->pem)
	{
		_key->pem = calloc(key->pem_length, sizeof(char));
		if (!_key->pem)
			goto out_fail;
		memcpy(_key->pem, key->pem, key->pem_length);
	}

	if (key->PrivateExponent)
	{
		_key->PrivateExponent = (BYTE*)malloc(key->PrivateExponentLength);

		if (!_key->PrivateExponent)
			goto out_fail;

		CopyMemory(_key->PrivateExponent, key->PrivateExponent, key->PrivateExponentLength);
	}

	return _key;
out_fail:
	freerdp_key_free(_key);
	return NULL;
}

void freerdp_key_free(rdpRsaKey* key)
{
	if (!key)
		return;

	if (key->PrivateExponent)
		memset(key->PrivateExponent, 0, key->PrivateExponentLength);
	free(key->PrivateExponent);
	cert_info_free(&key->cert);
	free(key->pem);
	free(key);
}

BOOL cert_info_create(rdpCertInfo* dst, const BIGNUM* rsa, const BIGNUM* rsa_e)
{
	const rdpCertInfo empty = { 0 };

	WINPR_ASSERT(dst);
	WINPR_ASSERT(rsa);

	*dst = empty;

	if (!read_bignum(&dst->Modulus, &dst->ModulusLength, rsa, TRUE))
		goto fail;

	UINT32 len = sizeof(dst->exponent);
	BYTE* ptr = &dst->exponent[0];
	if (!read_bignum(&ptr, &len, rsa_e, FALSE))
		goto fail;
	return TRUE;

fail:
	cert_info_free(dst);
	return FALSE;
}

void cert_info_free(rdpCertInfo* info)
{
	WINPR_ASSERT(info);
	free(info->Modulus);
	info->ModulusLength = 0;
}

BOOL cert_info_allocate(rdpCertInfo* info, size_t size)
{
	WINPR_ASSERT(info);
	cert_info_free(info);

	info->Modulus = (BYTE*)malloc(size);

	if (!info->Modulus && (size > 0))
		return FALSE;
	info->ModulusLength = (UINT32)size;
	return TRUE;
}

BOOL cert_info_read_modulus(rdpCertInfo* info, size_t size, wStream* s)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, size))
		return FALSE;
	if (size > UINT32_MAX)
		return FALSE;
	if (!cert_info_allocate(info, size))
		return FALSE;
	Stream_Read(s, info->Modulus, info->ModulusLength);
	return TRUE;
}

BOOL cert_info_read_exponent(rdpCertInfo* info, size_t size, wStream* s)
{
	if (!Stream_CheckAndLogRequiredLength(TAG, s, size))
		return FALSE;
	if (size > 4)
		return FALSE;
	if (!info->Modulus || (info->ModulusLength == 0))
		return FALSE;
	Stream_Read(s, &info->exponent[4 - size], size);
	crypto_reverse(info->Modulus, info->ModulusLength);
	crypto_reverse(info->exponent, 4);
	return TRUE;
}

static BOOL cert_blob_copy(rdpCertBlob* dst, const rdpCertBlob* src)
{
	const rdpCertBlob empty = { 0 };
	WINPR_ASSERT(dst);
	WINPR_ASSERT(src);

	cert_blob_free(dst, TRUE);
	*dst = empty;

	dst->membio = BIO_s_secmem();
	if (!dst->membio)
		return FALSE;

	if (src->x509)
		X509_up_ref(dst->x509);

	return cert_info_copy(&dst->info, &src->info);
}

BOOL cert_clone_int(rdpCertificate* dst, const rdpCertificate* src)
{
	WINPR_ASSERT(dst);
	WINPR_ASSERT(src);

	certificate_free_x509_certificate_chain(dst);
	if (!certificate_resize_x509_certificate_chain(dst, src->count))
		return FALSE;

	for (UINT32 x = 0; x < src->count; x++)
	{
		const rdpCertBlob* srcblob = &src->array[x];
		rdpCertBlob* dstblob = &dst->array[x];

		if (!cert_blob_copy(dstblob, srcblob))
			return FALSE;
	}
	return TRUE;
}

rdpCertificate* certificate_clone(const rdpCertificate* certificate)
{
	if (!certificate)
		return NULL;

	rdpCertificate* _certificate = (rdpCertificate*)calloc(1, sizeof(rdpCertificate));

	if (!_certificate)
		return NULL;

	if (!cert_clone_int(_certificate, certificate))
		goto out_fail;

	return _certificate;
out_fail:

	freerdp_certificate_free(_certificate);
	return NULL;
}

/**
 * Instantiate new certificate module.
 * @return new certificate module
 */

rdpCertificate* freerdp_certificate_new(void)
{
	return (rdpCertificate*)calloc(1, sizeof(rdpCertificate));
}

/**
 * Free certificate module.
 * @param certificate certificate module to be freed
 */

void freerdp_certificate_free(rdpCertificate* certificate)
{
	if (!certificate)
		return;

	certificate_free_x509_certificate_chain(certificate);
	free(certificate);
}

rdpCertificate* freerdp_certificate_new_from_file(const char* file)
{
	rdpCertificate* cert = NULL;
	size_t size = 0;
	char* pem = read_pem_file(file, &size);
	if (!file)
		return NULL;

	cert = freerdp_certificate_new_from_pem(pem, size + 1);
fail:
	free(pem);
	return cert;
}

rdpCertificate* freerdp_certificate_new_from_pem(const char* pem, size_t length)
{
	RSA* rsa = NULL;
	rdpCertificate* cert = freerdp_certificate_new();

	if (!cert || !pem)
		goto fail;

	if (!certificate_ensure_array_size(cert, 1))
		goto fail;

	rdpCertBlob* blob = cert_get_blob_at(cert, 0);
	WINPR_ASSERT(blob);

	if (!cert_blob_from_pem(blob, pem, length))
		goto fail;
	return cert;

fail:
	freerdp_certificate_free(cert);
	return NULL;
}

static char* x509_to_pem(const rdpCertBlob* blob, size_t* plength)
{
	WINPR_ASSERT(blob);
	WINPR_ASSERT(plength);
	WINPR_ASSERT(blob->membio);

	const int rc = PEM_write_bio_X509(blob->membio, blob->x509);

	char* data = NULL;
	const long size = BIO_get_mem_data(blob->membio, &data);
	*plength = size;
	return data;
}

const char* freerdp_certificate_get_pem(const rdpCertificate* certificate, size_t* length)
{
	if (length)
		*length = 0;

	rdpCertBlob* blob = cert_get_blob_at(certificate, 0);
	if (!blob)
		return NULL;

	return x509_to_pem(blob, length);
}

const rdpCertInfo* freerdp_certificate_get_info(const rdpCertificate* certificate)
{
	if (!certificate)
		return NULL;
	const rdpCertBlob* blob = cert_get_const_blob_at(certificate, 0);
	if (!blob)
		return NULL;
	WINPR_ASSERT(blob->isRSA);
	return &blob->info;
}

rdpCertInfo* freerdp_certificate_get_info_writeable(rdpCertificate* certificate)
{
	if (!certificate || (certificate->count == 0))
		return NULL;
	return &certificate->array[0].info;
}

const BYTE* freerdp_key_get_exponent(const rdpRsaKey* key, size_t* exponent_length)
{
	if (exponent_length)
		*exponent_length = 0;
	if (!key)
		return NULL;

	WINPR_ASSERT(key->isRSA);
	if (exponent_length)
		*exponent_length = key->PrivateExponentLength;
	return key->PrivateExponent;
}

const rdpCertInfo* freerdp_key_get_cert_info(const rdpRsaKey* key)
{
	if (!key)
		return NULL;
	WINPR_ASSERT(key->isRSA);
	return &key->cert;
}

const char* freerdp_key_get_pem(const rdpRsaKey* key, size_t* length)
{
	if (length)
		*length = 0;
	if (!key)
		return NULL;

	if (length)
		*length = key->pem_length;
	return key->pem;
}

X509* freerdp_certificate_get_x509(const rdpCertificate* certificate)
{
	const rdpCertBlob* blob = cert_get_const_blob_at(certificate, 0);
	if (!blob)
		return NULL;
	return X509_dup(blob->x509);
}
