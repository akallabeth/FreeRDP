/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Security Support Provider Interface (SSPI)
 *
 * Copyright 2012-2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/windows.h>

#include <winpr/crt.h>
#include <winpr/ssl.h>
#include <winpr/print.h>

#include "sspi.h"

#include "sspi_winpr.h"

#include "../log.h"
#define TAG WINPR_TAG("sspi")

#define SEC_WINNT_AUTH_IDENTITY_VERSION 0x200
#define SEC_WINNT_AUTH_IDENTITY_VERSION_2 0x201

typedef struct _SEC_WINNT_AUTH_IDENTITY_EXA
{
	unsigned long Version;
	unsigned long Length;
	unsigned char* User;            //  Non-NULL terminated string.
	unsigned long UserLength;       //  # of characters (NOT bytes), not including NULL.
	unsigned char* Domain;          //  Non-NULL terminated string.
	unsigned long DomainLength;     //  # of characters (NOT bytes), not including NULL.
	unsigned char* Password;        //  Non-NULL terminated string.
	unsigned long PasswordLength;   //  # of characters (NOT bytes), not including NULL.
	unsigned long Flags;
	unsigned char* PackageList;
	unsigned long PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EXA, *PSEC_WINNT_AUTH_IDENTITY_EXA;

typedef struct _SEC_WINNT_AUTH_IDENTITY_EXW
{
	unsigned long Version;
	unsigned long Length;
	unsigned short* User;           //  Non-NULL terminated string.
	unsigned long UserLength;       //  # of characters (NOT bytes), not including NULL.
	unsigned short* Domain;         //  Non-NULL terminated string.
	unsigned long DomainLength;     //  # of characters (NOT bytes), not including NULL.
	unsigned short* Password;       //  Non-NULL terminated string.
	unsigned long PasswordLength;   //  # of characters (NOT bytes), not including NULL.
	unsigned long Flags;
	unsigned short* PackageList;
	unsigned long PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EXW, *PSEC_WINNT_AUTH_IDENTITY_EXW;

typedef struct _SEC_WINNT_AUTH_IDENTITY_EX2
{
	unsigned long Version; // contains SEC_WINNT_AUTH_IDENTITY_VERSION_2
	unsigned short cbHeaderLength;
	unsigned long cbStructureLength;
	unsigned long UserOffset;                // Non-NULL terminated string, unicode only
	unsigned short UserLength;               // # of bytes (NOT WCHARs), not including NULL.
	unsigned long DomainOffset;              // Non-NULL terminated string, unicode only
	unsigned short DomainLength;             // # of bytes (NOT WCHARs), not including NULL.
	unsigned long PackedCredentialsOffset;   // Non-NULL terminated string, unicode only
	unsigned short PackedCredentialsLength;  // # of bytes (NOT WCHARs), not including NULL.
	unsigned long Flags;
	unsigned long PackageListOffset;         // Non-NULL terminated string, unicode only
	unsigned short PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EX2, *PSEC_WINNT_AUTH_IDENTITY_EX2;

typedef struct
{
	UINT16* User;
	UINT32 UserLength;
	UINT16* Domain;
	UINT32 DomainLength;
	UINT16* Password;
	UINT32 PasswordLength;
	UINT32 Flags;
} SEC_WINNT_AUTH_IDENTITY_W, *PSEC_WINNT_AUTH_IDENTITY_W;

typedef struct
{
	BYTE* User;
	UINT32 UserLength;
	BYTE* Domain;
	UINT32 DomainLength;
	BYTE* Password;
	UINT32 PasswordLength;
	UINT32 Flags;
} SEC_WINNT_AUTH_IDENTITY_A, *PSEC_WINNT_AUTH_IDENTITY_A;

typedef union _SEC_WINNT_AUTH_IDENTITY_INFO
{
	SEC_WINNT_AUTH_IDENTITY_EXW AuthIdExw;
	SEC_WINNT_AUTH_IDENTITY_EXA AuthIdExa;
	SEC_WINNT_AUTH_IDENTITY_A AuthId_a;
	SEC_WINNT_AUTH_IDENTITY_W AuthId_w;
	SEC_WINNT_AUTH_IDENTITY_EX2 AuthIdEx2;
} SEC_WINNT_AUTH_IDENTITY_INFO, *PSEC_WINNT_AUTH_IDENTITY_INFO;

/* Authentication Functions: http://msdn.microsoft.com/en-us/library/windows/desktop/aa374731/ */

extern const SecPkgInfoA NTLM_SecPkgInfoA;
extern const SecPkgInfoW NTLM_SecPkgInfoW;
extern const SecurityFunctionTableA NTLM_SecurityFunctionTableA;
extern const SecurityFunctionTableW NTLM_SecurityFunctionTableW;

extern const SecPkgInfoA KERBEROS_SecPkgInfoA;
extern const SecPkgInfoW KERBEROS_SecPkgInfoW;
extern const SecurityFunctionTableA KERBEROS_SecurityFunctionTableA;
extern const SecurityFunctionTableW KERBEROS_SecurityFunctionTableW;

extern const SecPkgInfoA NEGOTIATE_SecPkgInfoA;
extern const SecPkgInfoW NEGOTIATE_SecPkgInfoW;
extern const SecurityFunctionTableA NEGOTIATE_SecurityFunctionTableA;
extern const SecurityFunctionTableW NEGOTIATE_SecurityFunctionTableW;

extern const SecPkgInfoA CREDSSP_SecPkgInfoA;
extern const SecPkgInfoW CREDSSP_SecPkgInfoW;
extern const SecurityFunctionTableA CREDSSP_SecurityFunctionTableA;
extern const SecurityFunctionTableW CREDSSP_SecurityFunctionTableW;

extern const SecPkgInfoA SCHANNEL_SecPkgInfoA;
extern const SecPkgInfoW SCHANNEL_SecPkgInfoW;
extern const SecurityFunctionTableA SCHANNEL_SecurityFunctionTableA;
extern const SecurityFunctionTableW SCHANNEL_SecurityFunctionTableW;

static const SecPkgInfoA* SecPkgInfoA_LIST[] =
{
	&NTLM_SecPkgInfoA,
	&KERBEROS_SecPkgInfoA,
	&NEGOTIATE_SecPkgInfoA,
	&CREDSSP_SecPkgInfoA,
	&SCHANNEL_SecPkgInfoA
};

static const SecPkgInfoW* SecPkgInfoW_LIST[] =
{
	&NTLM_SecPkgInfoW,
	&KERBEROS_SecPkgInfoW,
	&NEGOTIATE_SecPkgInfoW,
	&CREDSSP_SecPkgInfoW,
	&SCHANNEL_SecPkgInfoW
};

static SecurityFunctionTableA winpr_SecurityFunctionTableA;
static SecurityFunctionTableW winpr_SecurityFunctionTableW;

struct _SecurityFunctionTableA_NAME
{
	const SEC_CHAR* Name;
	const SecurityFunctionTableA* SecurityFunctionTable;
};
typedef struct _SecurityFunctionTableA_NAME SecurityFunctionTableA_NAME;

struct _SecurityFunctionTableW_NAME
{
	const SEC_WCHAR* Name;
	const SecurityFunctionTableW* SecurityFunctionTable;
};
typedef struct _SecurityFunctionTableW_NAME SecurityFunctionTableW_NAME;

static const SecurityFunctionTableA_NAME SecurityFunctionTableA_NAME_LIST[] =
{
	{ "NTLM", &NTLM_SecurityFunctionTableA },
	{ "Kerberos", &KERBEROS_SecurityFunctionTableA },
	{ "Negotiate", &NEGOTIATE_SecurityFunctionTableA },
	{ "CREDSSP", &CREDSSP_SecurityFunctionTableA },
	{ "Schannel", &SCHANNEL_SecurityFunctionTableA }
};

static const WCHAR NTLM_NAME_W[] = { 'N', 'T', 'L', 'M', '\0' };
static const WCHAR KERBEROS_NAME_W[] = { 'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', '\0' };
static const WCHAR NEGOTIATE_NAME_W[] = { 'N', 'e', 'g', 'o', 't', 'i', 'a', 't', 'e', '\0' };
static const WCHAR CREDSSP_NAME_W[] = { 'C', 'r', 'e', 'd', 'S', 'S', 'P', '\0' };
static const WCHAR SCHANNEL_NAME_W[] = { 'S', 'c', 'h', 'a', 'n', 'n', 'e', 'l', '\0' };

static const SecurityFunctionTableW_NAME SecurityFunctionTableW_NAME_LIST[] =
{
	{ NTLM_NAME_W, &NTLM_SecurityFunctionTableW },
	{ KERBEROS_NAME_W, &KERBEROS_SecurityFunctionTableW },
	{ NEGOTIATE_NAME_W, &NEGOTIATE_SecurityFunctionTableW },
	{ CREDSSP_NAME_W, &CREDSSP_SecurityFunctionTableW },
	{ SCHANNEL_NAME_W, &SCHANNEL_SecurityFunctionTableW }
};

#define SecHandle_LOWER_MAX	0xFFFFFFFF
#define SecHandle_UPPER_MAX	0xFFFFFFFE

struct _CONTEXT_BUFFER_ALLOC_ENTRY
{
	void* contextBuffer;
	UINT32 allocatorIndex;
};
typedef struct _CONTEXT_BUFFER_ALLOC_ENTRY CONTEXT_BUFFER_ALLOC_ENTRY;

struct _CONTEXT_BUFFER_ALLOC_TABLE
{
	UINT32 cEntries;
	UINT32 cMaxEntries;
	CONTEXT_BUFFER_ALLOC_ENTRY* entries;
};
typedef struct _CONTEXT_BUFFER_ALLOC_TABLE CONTEXT_BUFFER_ALLOC_TABLE;

static CONTEXT_BUFFER_ALLOC_TABLE ContextBufferAllocTable = { 0 };


static DWORD sspi_AuthIdentityType(PSEC_WINNT_AUTH_IDENTITY_OPAQUE identity)
{
	const DWORD* type = identity;

	if (!type)
		return 0;

	return *type;
}

static BOOL copyIfA(BYTE** dst, const void* data, size_t length)
{
	if (!dst)
		return FALSE;

	if (!data && (length != 0))
		return FALSE;

	if (length == 0)
		return TRUE;

	*dst = malloc(length);

	if (!*dst)
		return FALSE;

	memcpy(*dst, data, length);
	return TRUE;
}

static BOOL copyIf(UINT16** dst, const UINT16* data, size_t length)
{
	return copyIfA((BYTE**)dst, data, length * sizeof(WCHAR));
}

static BOOL copyAndSetIf(UINT16** dst, const UINT16* data, unsigned long* length)
{
	const size_t len = _wcslen(data);

	if (!length)
		return FALSE;

	*length = len;
	return copyIf(dst, data, len);
}

static BOOL convertIf(UINT16** dst, const char* data, UINT32* length)
{
	if (!dst || !length)
		return FALSE;

	if (!data)
	{
		*length = 0;
		return TRUE;
	}

	const int status = ConvertToUnicode(CP_UTF8, 0, data, -1, dst, 0);

	if (status <= 0)
		return FALSE;

	*length = (UINT32)status - 1;
	return TRUE;
}

static int sspi_ContextBufferAllocTableNew(void)
{
	size_t size;
	ContextBufferAllocTable.entries = NULL;
	ContextBufferAllocTable.cEntries = 0;
	ContextBufferAllocTable.cMaxEntries = 4;
	size = sizeof(CONTEXT_BUFFER_ALLOC_ENTRY) * ContextBufferAllocTable.cMaxEntries;
	ContextBufferAllocTable.entries = (CONTEXT_BUFFER_ALLOC_ENTRY*) calloc(1, size);

	if (!ContextBufferAllocTable.entries)
		return -1;

	return 1;
}

static int sspi_ContextBufferAllocTableGrow(void)
{
	size_t size;
	CONTEXT_BUFFER_ALLOC_ENTRY* entries;
	ContextBufferAllocTable.cEntries = 0;
	ContextBufferAllocTable.cMaxEntries *= 2;
	size = sizeof(CONTEXT_BUFFER_ALLOC_ENTRY) * ContextBufferAllocTable.cMaxEntries;

	if (!size)
		return -1;

	entries = (CONTEXT_BUFFER_ALLOC_ENTRY*) realloc(ContextBufferAllocTable.entries, size);

	if (!entries)
	{
		free(ContextBufferAllocTable.entries);
		return -1;
	}

	ContextBufferAllocTable.entries = entries;
	ZeroMemory((void*) &ContextBufferAllocTable.entries[ContextBufferAllocTable.cMaxEntries / 2],
	           size / 2);
	return 1;
}

static void sspi_ContextBufferAllocTableFree(void)
{
	if (ContextBufferAllocTable.cEntries != 0)
		WLog_ERR(TAG, "ContextBufferAllocTable.entries == %"PRIu32, ContextBufferAllocTable.cEntries);

	ContextBufferAllocTable.cEntries = ContextBufferAllocTable.cMaxEntries = 0;
	free(ContextBufferAllocTable.entries);
	ContextBufferAllocTable.entries = NULL;
}

static void* sspi_ContextBufferAlloc(UINT32 allocatorIndex, size_t size)
{
	UINT32 index;
	void* contextBuffer;

	for (index = 0; index < ContextBufferAllocTable.cMaxEntries; index++)
	{
		if (!ContextBufferAllocTable.entries[index].contextBuffer)
		{
			contextBuffer = calloc(1, size);

			if (!contextBuffer)
				return NULL;

			ContextBufferAllocTable.cEntries++;
			ContextBufferAllocTable.entries[index].contextBuffer = contextBuffer;
			ContextBufferAllocTable.entries[index].allocatorIndex = allocatorIndex;
			return ContextBufferAllocTable.entries[index].contextBuffer;
		}
	}

	/* no available entry was found, the table needs to be grown */

	if (sspi_ContextBufferAllocTableGrow() < 0)
		return NULL;

	/* the next call to sspi_ContextBufferAlloc() should now succeed */
	return sspi_ContextBufferAlloc(allocatorIndex, size);
}

SSPI_CREDENTIALS* sspi_CredentialsNew(void)
{
	SSPI_CREDENTIALS* credentials;
	credentials = (SSPI_CREDENTIALS*) calloc(1, sizeof(SSPI_CREDENTIALS));
	return credentials;
}

void sspi_CredentialsFree(SSPI_CREDENTIALS* credentials)
{
	if (!credentials)
		return;

	sspi_FreeAuthIdentity(credentials->identity);
	free(credentials);
}

void* sspi_SecBufferAlloc(PSecBuffer SecBuffer, ULONG size)
{
	if (!SecBuffer)
		return NULL;

	SecBuffer->pvBuffer = calloc(1, size);

	if (!SecBuffer->pvBuffer)
		return NULL;

	SecBuffer->cbBuffer = size;
	return SecBuffer->pvBuffer;
}

void sspi_SecBufferFree(PSecBuffer SecBuffer)
{
	if (!SecBuffer)
		return;

	if (SecBuffer->pvBuffer)
		memset(SecBuffer->pvBuffer, 0, SecBuffer->cbBuffer);

	free(SecBuffer->pvBuffer);
	SecBuffer->pvBuffer = NULL;
	SecBuffer->cbBuffer = 0;
}

SecHandle* sspi_SecureHandleAlloc(void)
{
	SecHandle* handle = (SecHandle*) calloc(1, sizeof(SecHandle));

	if (!handle)
		return NULL;

	SecInvalidateHandle(handle);
	return handle;
}

void* sspi_SecureHandleGetLowerPointer(SecHandle* handle)
{
	void* pointer;

	if (!handle || !SecIsValidHandle(handle) || !handle->dwLower)
		return NULL;

	pointer = (void*) ~((size_t) handle->dwLower);
	return pointer;
}

void sspi_SecureHandleInvalidate(SecHandle* handle)
{
	if (!handle)
		return;

	handle->dwLower = 0;
	handle->dwUpper = 0;
}

void sspi_SecureHandleSetLowerPointer(SecHandle* handle, void* pointer)
{
	if (!handle)
		return;

	handle->dwLower = (ULONG_PTR)(~((size_t) pointer));
}

void* sspi_SecureHandleGetUpperPointer(SecHandle* handle)
{
	void* pointer;

	if (!handle || !SecIsValidHandle(handle) || !handle->dwUpper)
		return NULL;

	pointer = (void*) ~((size_t) handle->dwUpper);
	return pointer;
}

void sspi_SecureHandleSetUpperPointer(SecHandle* handle, void* pointer)
{
	if (!handle)
		return;

	handle->dwUpper = (ULONG_PTR)(~((size_t) pointer));
}

void sspi_SecureHandleFree(SecHandle* handle)
{
	free(handle);
}

int sspi_SetAuthIdentity(PSEC_WINNT_AUTH_IDENTITY_OPAQUE* identity, const char* user,
                         const char* domain,
                         const char* password)
{
	int rc;
	int unicodePasswordLenW;
	LPWSTR unicodePassword = NULL;
	unicodePasswordLenW = ConvertToUnicode(CP_UTF8, 0, password, -1, &unicodePassword, 0);

	if (unicodePasswordLenW <= 0)
		return -1;

	rc = sspi_SetAuthIdentityWithUnicodePassword(identity, user, domain, unicodePassword,
	        (ULONG)(unicodePasswordLenW - 1));
	free(unicodePassword);
	return rc;
}

SECURITY_STATUS sspi_EncodeStringsAsAuthIdentity(PCWSTR user, PCWSTR domain,
        PCWSTR pszPackedCredentialsString, PSEC_WINNT_AUTH_IDENTITY_OPAQUE* raw_identity)
{
	PSEC_WINNT_AUTH_IDENTITY_INFO identity;

	if (!raw_identity)
		return SEC_E_INVALID_PARAMETER;

	sspi_FreeAuthIdentity(*raw_identity);
	*raw_identity = NULL;
	identity = calloc(1, sizeof(SEC_WINNT_AUTH_IDENTITY_EXW));

	if (!identity)
		return SEC_E_INSUFFICIENT_MEMORY;

	identity->AuthIdExw.Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
	identity->AuthIdExw.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	if (!copyAndSetIf(&identity->AuthIdExw.Domain, domain, &identity->AuthIdExw.DomainLength))
		goto fail;

	if (!copyAndSetIf(&identity->AuthIdExw.Password, pszPackedCredentialsString,
	                  &identity->AuthIdExw.PasswordLength))
		goto fail;

	if (!copyAndSetIf(&identity->AuthIdExw.User, user, &identity->AuthIdExw.UserLength))
		goto fail;

	*raw_identity = identity;
	return SEC_E_OK;
fail:
	sspi_FreeAuthIdentity(identity);
	return SEC_E_INSUFFICIENT_MEMORY;
}

SECURITY_STATUS SEC_ENTRY sspi_EncodeAuthIdentityAsStrings(
    const PSEC_WINNT_AUTH_IDENTITY_OPAQUE pAuthIdentity,
    PCWSTR* ppszUserName, PCWSTR* ppszDomainName,
    PCWSTR* ppszPackedCredentialsString)
{
	PSEC_WINNT_AUTH_IDENTITY_INFO identity = pAuthIdentity;

	switch (sspi_AuthIdentityType(pAuthIdentity))
	{
		case SEC_WINNT_AUTH_IDENTITY_VERSION:
			if ((identity->AuthIdExw.Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE) == 0)
				return SEC_E_INVALID_HANDLE;

			*ppszUserName = identity->AuthIdExw.User;
			*ppszDomainName = identity->AuthIdExw.Domain;
			*ppszPackedCredentialsString = identity->AuthIdExw.Password;
			return SEC_E_OK;

		case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
		default:
			return SEC_E_INVALID_HANDLE;
	}
}

int sspi_SetAuthIdentityWithUnicodePassword(PSEC_WINNT_AUTH_IDENTITY_OPAQUE* identity,
        const char* user,
        const char* domain, LPCWSTR password, ULONG passwordLength)
{
	PWCHAR userW = NULL;
	PWCHAR domainW = NULL;
	SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;

	if (!convertIf(&userW, user, NULL))
		goto fail;

	if (!convertIf(&domainW, domain, NULL))
		goto fail;

	status = sspi_EncodeStringsAsAuthIdentity(userW, domainW, password, identity);
fail:
	free(userW);
	free(domainW);
	return status;
}

int sspi_CopyAuthIdentity(const PSEC_WINNT_AUTH_IDENTITY_OPAQUE psrcIdentity,
                          PSEC_WINNT_AUTH_IDENTITY_OPAQUE pidentity)
{
	const PSEC_WINNT_AUTH_IDENTITY_INFO srcIdentity = psrcIdentity;
	PSEC_WINNT_AUTH_IDENTITY_INFO identity = pidentity;

	switch (sspi_AuthIdentityType(psrcIdentity))
	{
		case SEC_WINNT_AUTH_IDENTITY_VERSION:
			*identity = *srcIdentity;

			if (identity->AuthIdExw.Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
			{
				if (!copyIf(&identity->AuthIdExw.User, srcIdentity->AuthIdExw.User,
				            srcIdentity->AuthIdExw.UserLength))
					goto fail;

				if (!copyIf(&identity->AuthIdExw.Domain, srcIdentity->AuthIdExw.Domain,
				            srcIdentity->AuthIdExw.DomainLength))
					goto fail;

				if (!copyIf(&identity->AuthIdExw.Password, srcIdentity->AuthIdExw.Password,
				            srcIdentity->AuthIdExw.PasswordLength))
					goto fail;

				if (!copyIf(&identity->AuthIdExw.PackageList, srcIdentity->AuthIdExw.PackageList,
				            srcIdentity->AuthIdExw.PackageListLength))
					goto fail;
			}

			if (identity->AuthIdExa.Flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
			{
				if (!copyIfA(&identity->AuthIdExa.User, srcIdentity->AuthIdExa.User,
				             srcIdentity->AuthIdExa.UserLength))
					goto fail;

				if (!copyIfA(&identity->AuthIdExa.Domain, srcIdentity->AuthIdExa.Domain,
				             srcIdentity->AuthIdExa.DomainLength))
					goto fail;

				if (!copyIfA(&identity->AuthIdExa.Password, srcIdentity->AuthIdExa.Password,
				             srcIdentity->AuthIdExa.PasswordLength))
					goto fail;

				if (!copyIfA(&identity->AuthIdExa.PackageList, srcIdentity->AuthIdExa.PackageList,
				             srcIdentity->AuthIdExa.PackageListLength))
					goto fail;
			}

			break;

		case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
			// TODO
			break;

		default:
			*identity = *srcIdentity;

			if (identity->AuthId_w.Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
			{
				if (!copyIf(&identity->AuthId_w.User, srcIdentity->AuthId_w.User, srcIdentity->AuthId_w.UserLength))
					goto fail;

				if (!copyIf(&identity->AuthId_w.Domain, srcIdentity->AuthId_w.Domain,
				            srcIdentity->AuthId_w.DomainLength))
					goto fail;

				if (!copyIf(&identity->AuthId_w.Password, srcIdentity->AuthId_w.Password,
				            srcIdentity->AuthId_w.PasswordLength))
					goto fail;
			}

			if (identity->AuthId_a.Flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
			{
				if (!copyIfA(&identity->AuthId_a.User, srcIdentity->AuthId_a.User,
				             srcIdentity->AuthId_a.UserLength))
					goto fail;

				if (!copyIfA(&identity->AuthId_a.Domain, srcIdentity->AuthId_a.Domain,
				             srcIdentity->AuthId_a.DomainLength))
					goto fail;

				if (!copyIfA(&identity->AuthId_a.Password, srcIdentity->AuthId_a.Password,
				             srcIdentity->AuthId_a.PasswordLength))
					goto fail;
			}

			break;
	}

	return 1;
fail:
	sspi_ZeroAuthIdentity(pidentity);
	return -1;
}

void sspi_FreeAuthIdentity(PSEC_WINNT_AUTH_IDENTITY_OPAQUE pidentity)
{
	PSEC_WINNT_AUTH_IDENTITY_INFO identity = pidentity;

	if (!identity)
		return;

	sspi_ZeroAuthIdentity(identity);

	switch (sspi_AuthIdentityType(identity))
	{
		case SEC_WINNT_AUTH_IDENTITY_VERSION:
			sspi_LocalFree(identity->AuthIdExw.Domain);
			sspi_LocalFree(identity->AuthIdExw.Password);
			sspi_LocalFree(identity->AuthIdExw.User);
			sspi_LocalFree(identity->AuthIdExw.PackageList);
			break;

		case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
			break;

		default:
			sspi_LocalFree(identity->AuthId_w.Domain);
			sspi_LocalFree(identity->AuthId_w.User);
			sspi_LocalFree(identity->AuthId_w.Password);
			break;
	}

	sspi_LocalFree(identity);
}

void sspi_ZeroAuthIdentity(PSEC_WINNT_AUTH_IDENTITY_OPAQUE pidentity)
{
	PSEC_WINNT_AUTH_IDENTITY_INFO identity = pidentity;

	if (!identity)
		return;

	switch (sspi_AuthIdentityType(pidentity))
	{
		case SEC_WINNT_AUTH_IDENTITY_VERSION:
			memset(identity->AuthIdExw.Domain, 0, identity->AuthIdExw.DomainLength);
			memset(identity->AuthIdExw.Password, 0, identity->AuthIdExw.PasswordLength);
			memset(identity->AuthIdExw.User, 0, identity->AuthIdExw.UserLength);
			memset(identity->AuthIdExw.PackageList, 0, identity->AuthIdExw.PackageListLength);
			break;

		case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
			break;

		default:
			memset(identity->AuthId_w.Domain, 0, identity->AuthId_w.DomainLength);
			memset(identity->AuthId_w.Password, 0, identity->AuthId_w.PasswordLength);
			memset(identity->AuthId_w.User, 0, identity->AuthId_w.UserLength);
			break;
	}
}

void sspi_LocalFree(PVOID buffer)
{
	free(buffer);
}

PSecBuffer sspi_FindSecBuffer(PSecBufferDesc pMessage, ULONG BufferType)
{
	ULONG index;
	PSecBuffer pSecBuffer = NULL;

	for (index = 0; index < pMessage->cBuffers; index++)
	{
		if (pMessage->pBuffers[index].BufferType == BufferType)
		{
			pSecBuffer = &pMessage->pBuffers[index];
			break;
		}
	}

	return pSecBuffer;
}

static BOOL CALLBACK sspi_init(PINIT_ONCE InitOnce, PVOID Parameter, PVOID* Context)
{
	winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
	sspi_ContextBufferAllocTableNew();
	return TRUE;
}

void sspi_GlobalInit(void)
{
	static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
	DWORD flags = 0;
	InitOnceExecuteOnce(&once, sspi_init, &flags, NULL);
}

void sspi_GlobalFinish(void)
{
	sspi_ContextBufferAllocTableFree();
}

static const SecurityFunctionTableA* sspi_GetSecurityFunctionTableAByNameA(const SEC_CHAR* Name)
{
	int index;
	UINT32 cPackages;
	cPackages = sizeof(SecPkgInfoA_LIST) / sizeof(*(SecPkgInfoA_LIST));

	for (index = 0; index < (int) cPackages; index++)
	{
		if (strcmp(Name, SecurityFunctionTableA_NAME_LIST[index].Name) == 0)
		{
			return SecurityFunctionTableA_NAME_LIST[index].SecurityFunctionTable;
		}
	}

	return NULL;
}

static const SecurityFunctionTableW* sspi_GetSecurityFunctionTableWByNameW(const SEC_WCHAR* Name)
{
	int index;
	UINT32 cPackages;
	cPackages = sizeof(SecPkgInfoW_LIST) / sizeof(*(SecPkgInfoW_LIST));

	for (index = 0; index < (int) cPackages; index++)
	{
		if (lstrcmpW(Name, SecurityFunctionTableW_NAME_LIST[index].Name) == 0)
		{
			return SecurityFunctionTableW_NAME_LIST[index].SecurityFunctionTable;
		}
	}

	return NULL;
}

static const SecurityFunctionTableW* sspi_GetSecurityFunctionTableWByNameA(const SEC_CHAR* Name)
{
	int status;
	SEC_WCHAR* NameW = NULL;
	const SecurityFunctionTableW* table;
	status = ConvertToUnicode(CP_UTF8, 0, Name, -1, &NameW, 0);

	if (status <= 0)
		return NULL;

	table = sspi_GetSecurityFunctionTableWByNameW(NameW);
	free(NameW);
	return table;
}

static void FreeContextBuffer_EnumerateSecurityPackages(void* contextBuffer);
static void FreeContextBuffer_QuerySecurityPackageInfo(void* contextBuffer);

static void sspi_ContextBufferFree(void* contextBuffer)
{
	UINT32 index;
	UINT32 allocatorIndex;

	for (index = 0; index < ContextBufferAllocTable.cMaxEntries; index++)
	{
		if (contextBuffer == ContextBufferAllocTable.entries[index].contextBuffer)
		{
			contextBuffer = ContextBufferAllocTable.entries[index].contextBuffer;
			allocatorIndex = ContextBufferAllocTable.entries[index].allocatorIndex;
			ContextBufferAllocTable.cEntries--;
			ContextBufferAllocTable.entries[index].allocatorIndex = 0;
			ContextBufferAllocTable.entries[index].contextBuffer = NULL;

			switch (allocatorIndex)
			{
				case EnumerateSecurityPackagesIndex:
					FreeContextBuffer_EnumerateSecurityPackages(contextBuffer);
					break;

				case QuerySecurityPackageInfoIndex:
					FreeContextBuffer_QuerySecurityPackageInfo(contextBuffer);
					break;
			}
		}
	}
}

/**
 * Standard SSPI API
 */

/* Package Management */

static SECURITY_STATUS SEC_ENTRY winpr_EnumerateSecurityPackagesW(ULONG* pcPackages,
        PSecPkgInfoW* ppPackageInfo)
{
	int index;
	size_t size;
	UINT32 cPackages;
	SecPkgInfoW* pPackageInfo;
	cPackages = sizeof(SecPkgInfoW_LIST) / sizeof(*(SecPkgInfoW_LIST));
	size = sizeof(SecPkgInfoW) * cPackages;
	pPackageInfo = (SecPkgInfoW*) sspi_ContextBufferAlloc(EnumerateSecurityPackagesIndex, size);

	if (!pPackageInfo)
		return SEC_E_INSUFFICIENT_MEMORY;

	for (index = 0; index < (int) cPackages; index++)
	{
		pPackageInfo[index].fCapabilities = SecPkgInfoW_LIST[index]->fCapabilities;
		pPackageInfo[index].wVersion = SecPkgInfoW_LIST[index]->wVersion;
		pPackageInfo[index].wRPCID = SecPkgInfoW_LIST[index]->wRPCID;
		pPackageInfo[index].cbMaxToken = SecPkgInfoW_LIST[index]->cbMaxToken;
		pPackageInfo[index].Name = _wcsdup(SecPkgInfoW_LIST[index]->Name);
		pPackageInfo[index].Comment = _wcsdup(SecPkgInfoW_LIST[index]->Comment);
	}

	*(pcPackages) = cPackages;
	*(ppPackageInfo) = pPackageInfo;
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY winpr_EnumerateSecurityPackagesA(ULONG* pcPackages,
        PSecPkgInfoA* ppPackageInfo)
{
	int index;
	size_t size;
	UINT32 cPackages;
	SecPkgInfoA* pPackageInfo;
	cPackages = sizeof(SecPkgInfoA_LIST) / sizeof(*(SecPkgInfoA_LIST));
	size = sizeof(SecPkgInfoA) * cPackages;
	pPackageInfo = (SecPkgInfoA*) sspi_ContextBufferAlloc(EnumerateSecurityPackagesIndex, size);

	if (!pPackageInfo)
		return SEC_E_INSUFFICIENT_MEMORY;

	for (index = 0; index < (int) cPackages; index++)
	{
		pPackageInfo[index].fCapabilities = SecPkgInfoA_LIST[index]->fCapabilities;
		pPackageInfo[index].wVersion = SecPkgInfoA_LIST[index]->wVersion;
		pPackageInfo[index].wRPCID = SecPkgInfoA_LIST[index]->wRPCID;
		pPackageInfo[index].cbMaxToken = SecPkgInfoA_LIST[index]->cbMaxToken;
		pPackageInfo[index].Name = _strdup(SecPkgInfoA_LIST[index]->Name);
		pPackageInfo[index].Comment = _strdup(SecPkgInfoA_LIST[index]->Comment);

		if (!pPackageInfo[index].Name || !pPackageInfo[index].Comment)
		{
			sspi_ContextBufferFree(pPackageInfo);
			return SEC_E_INSUFFICIENT_MEMORY;
		}
	}

	*(pcPackages) = cPackages;
	*(ppPackageInfo) = pPackageInfo;
	return SEC_E_OK;
}

static void FreeContextBuffer_EnumerateSecurityPackages(void* contextBuffer)
{
	int index;
	UINT32 cPackages;
	SecPkgInfoA* pPackageInfo = (SecPkgInfoA*) contextBuffer;
	cPackages = sizeof(SecPkgInfoA_LIST) / sizeof(*(SecPkgInfoA_LIST));

	for (index = 0; index < (int) cPackages; index++)
	{
		free(pPackageInfo[index].Name);
		free(pPackageInfo[index].Comment);
	}

	free(pPackageInfo);
}

SecurityFunctionTableW* SEC_ENTRY winpr_InitSecurityInterfaceW(void)
{
	return &winpr_SecurityFunctionTableW;
}

SecurityFunctionTableA* SEC_ENTRY winpr_InitSecurityInterfaceA(void)
{
	return &winpr_SecurityFunctionTableA;
}

static SECURITY_STATUS SEC_ENTRY winpr_QuerySecurityPackageInfoW(SEC_WCHAR* pszPackageName,
        PSecPkgInfoW* ppPackageInfo)
{
	int index;
	size_t size;
	UINT32 cPackages;
	SecPkgInfoW* pPackageInfo;
	cPackages = sizeof(SecPkgInfoW_LIST) / sizeof(*(SecPkgInfoW_LIST));

	for (index = 0; index < (int) cPackages; index++)
	{
		if (lstrcmpW(pszPackageName, SecPkgInfoW_LIST[index]->Name) == 0)
		{
			size = sizeof(SecPkgInfoW);
			pPackageInfo = (SecPkgInfoW*) sspi_ContextBufferAlloc(QuerySecurityPackageInfoIndex, size);

			if (!pPackageInfo)
				return SEC_E_INSUFFICIENT_MEMORY;

			pPackageInfo->fCapabilities = SecPkgInfoW_LIST[index]->fCapabilities;
			pPackageInfo->wVersion = SecPkgInfoW_LIST[index]->wVersion;
			pPackageInfo->wRPCID = SecPkgInfoW_LIST[index]->wRPCID;
			pPackageInfo->cbMaxToken = SecPkgInfoW_LIST[index]->cbMaxToken;
			pPackageInfo->Name = _wcsdup(SecPkgInfoW_LIST[index]->Name);
			pPackageInfo->Comment = _wcsdup(SecPkgInfoW_LIST[index]->Comment);
			*(ppPackageInfo) = pPackageInfo;
			return SEC_E_OK;
		}
	}

	*(ppPackageInfo) = NULL;
	return SEC_E_SECPKG_NOT_FOUND;
}

static SECURITY_STATUS SEC_ENTRY winpr_QuerySecurityPackageInfoA(SEC_CHAR* pszPackageName,
        PSecPkgInfoA* ppPackageInfo)
{
	int index;
	size_t size;
	UINT32 cPackages;
	SecPkgInfoA* pPackageInfo;
	cPackages = sizeof(SecPkgInfoA_LIST) / sizeof(*(SecPkgInfoA_LIST));

	for (index = 0; index < (int) cPackages; index++)
	{
		if (strcmp(pszPackageName, SecPkgInfoA_LIST[index]->Name) == 0)
		{
			size = sizeof(SecPkgInfoA);
			pPackageInfo = (SecPkgInfoA*) sspi_ContextBufferAlloc(QuerySecurityPackageInfoIndex, size);

			if (!pPackageInfo)
				return SEC_E_INSUFFICIENT_MEMORY;

			pPackageInfo->fCapabilities = SecPkgInfoA_LIST[index]->fCapabilities;
			pPackageInfo->wVersion = SecPkgInfoA_LIST[index]->wVersion;
			pPackageInfo->wRPCID = SecPkgInfoA_LIST[index]->wRPCID;
			pPackageInfo->cbMaxToken = SecPkgInfoA_LIST[index]->cbMaxToken;
			pPackageInfo->Name = _strdup(SecPkgInfoA_LIST[index]->Name);
			pPackageInfo->Comment = _strdup(SecPkgInfoA_LIST[index]->Comment);

			if (!pPackageInfo->Name || !pPackageInfo->Comment)
			{
				sspi_ContextBufferFree(pPackageInfo);
				return SEC_E_INSUFFICIENT_MEMORY;
			}

			*(ppPackageInfo) = pPackageInfo;
			return SEC_E_OK;
		}
	}

	*(ppPackageInfo) = NULL;
	return SEC_E_SECPKG_NOT_FOUND;
}

void FreeContextBuffer_QuerySecurityPackageInfo(void* contextBuffer)
{
	SecPkgInfo* pPackageInfo = (SecPkgInfo*) contextBuffer;

	if (!pPackageInfo)
		return;

	free(pPackageInfo->Name);
	free(pPackageInfo->Comment);
	free(pPackageInfo);
}

/* Credential Management */

static SECURITY_STATUS SEC_ENTRY winpr_AcquireCredentialsHandleW(SEC_WCHAR* pszPrincipal,
        SEC_WCHAR* pszPackage,
        ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
        void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table = sspi_GetSecurityFunctionTableWByNameW(pszPackage);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->AcquireCredentialsHandleW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse,
	         pvLogonID, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "AcquireCredentialsHandleW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_AcquireCredentialsHandleA(SEC_CHAR* pszPrincipal,
        SEC_CHAR* pszPackage,
        ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
        void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table = sspi_GetSecurityFunctionTableAByNameA(pszPackage);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->AcquireCredentialsHandleA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->AcquireCredentialsHandleA(pszPrincipal, pszPackage, fCredentialUse,
	         pvLogonID, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "AcquireCredentialsHandleA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_ExportSecurityContext(PCtxtHandle phContext, ULONG fFlags,
        PSecBuffer pPackedContext, HANDLE* pToken)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->ExportSecurityContext)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->ExportSecurityContext(phContext, fFlags, pPackedContext, pToken);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "ExportSecurityContext status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_FreeCredentialsHandle(PCredHandle phCredential)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->FreeCredentialsHandle)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->FreeCredentialsHandle(phCredential);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "FreeCredentialsHandle status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_ImportSecurityContextW(SEC_WCHAR* pszPackage,
        PSecBuffer pPackedContext, HANDLE pToken, PCtxtHandle phContext)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->ImportSecurityContextW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->ImportSecurityContextW(pszPackage, pPackedContext, pToken, phContext);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "ImportSecurityContextW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_ImportSecurityContextA(SEC_CHAR* pszPackage,
        PSecBuffer pPackedContext, HANDLE pToken, PCtxtHandle phContext)
{
	char* Name = NULL;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->ImportSecurityContextA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->ImportSecurityContextA(pszPackage, pPackedContext, pToken, phContext);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "ImportSecurityContextA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_QueryCredentialsAttributesW(PCredHandle phCredential,
        ULONG ulAttribute, void* pBuffer)
{
	SEC_WCHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_WCHAR*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameW(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->QueryCredentialsAttributesW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->QueryCredentialsAttributesW(phCredential, ulAttribute, pBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "QueryCredentialsAttributesW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_QueryCredentialsAttributesA(PCredHandle phCredential,
        ULONG ulAttribute, void* pBuffer)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->QueryCredentialsAttributesA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->QueryCredentialsAttributesA(phCredential, ulAttribute, pBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "QueryCredentialsAttributesA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

/* Context Management */

static SECURITY_STATUS SEC_ENTRY winpr_AcceptSecurityContext(PCredHandle phCredential,
        PCtxtHandle phContext,
        PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext,
        PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->AcceptSecurityContext)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->AcceptSecurityContext(phCredential, phContext, pInput, fContextReq,
	                                      TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsTimeStamp);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "AcceptSecurityContext status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_ApplyControlToken(PCtxtHandle phContext,
        PSecBufferDesc pInput)
{
	char* Name = NULL;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->ApplyControlToken)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->ApplyControlToken(phContext, pInput);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "ApplyControlToken status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_CompleteAuthToken(PCtxtHandle phContext,
        PSecBufferDesc pToken)
{
	char* Name = NULL;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->CompleteAuthToken)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->CompleteAuthToken(phContext, pToken);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "CompleteAuthToken status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_DeleteSecurityContext(PCtxtHandle phContext)
{
	char* Name = NULL;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->DeleteSecurityContext)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->DeleteSecurityContext(phContext);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "DeleteSecurityContext status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_FreeContextBuffer(void* pvContextBuffer)
{
	if (!pvContextBuffer)
		return SEC_E_INVALID_HANDLE;

	sspi_ContextBufferFree(pvContextBuffer);
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY winpr_ImpersonateSecurityContext(PCtxtHandle phContext)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->ImpersonateSecurityContext)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->ImpersonateSecurityContext(phContext);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "ImpersonateSecurityContext status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_InitializeSecurityContextW(PCredHandle phCredential,
        PCtxtHandle phContext,
        SEC_WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
        PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
        PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->InitializeSecurityContextW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->InitializeSecurityContextW(phCredential, phContext,
	         pszTargetName, fContextReq, Reserved1, TargetDataRep,
	         pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "InitializeSecurityContextW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_InitializeSecurityContextA(PCredHandle phCredential,
        PCtxtHandle phContext,
        SEC_CHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
        PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
        PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phCredential);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->InitializeSecurityContextA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->InitializeSecurityContextA(phCredential, phContext,
	         pszTargetName, fContextReq, Reserved1, TargetDataRep,
	         pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "InitializeSecurityContextA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_QueryContextAttributesW(PCtxtHandle phContext,
        ULONG ulAttribute,
        void* pBuffer)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->QueryContextAttributesW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->QueryContextAttributesW(phContext, ulAttribute, pBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "QueryContextAttributesW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_QueryContextAttributesA(PCtxtHandle phContext,
        ULONG ulAttribute,
        void* pBuffer)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->QueryContextAttributesA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->QueryContextAttributesA(phContext, ulAttribute, pBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "QueryContextAttributesA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_QuerySecurityContextToken(PCtxtHandle phContext,
        HANDLE* phToken)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->QuerySecurityContextToken)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->QuerySecurityContextToken(phContext, phToken);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "QuerySecurityContextToken status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_SetContextAttributesW(PCtxtHandle phContext,
        ULONG ulAttribute,
        void* pBuffer, ULONG cbBuffer)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->SetContextAttributesW)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->SetContextAttributesW(phContext, ulAttribute, pBuffer, cbBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "SetContextAttributesW status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_SetContextAttributesA(PCtxtHandle phContext,
        ULONG ulAttribute,
        void* pBuffer, ULONG cbBuffer)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->SetContextAttributesA)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->SetContextAttributesA(phContext, ulAttribute, pBuffer, cbBuffer);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "SetContextAttributesA status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_RevertSecurityContext(PCtxtHandle phContext)
{
	SEC_CHAR* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableW* table;
	Name = (SEC_CHAR*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableWByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->RevertSecurityContext)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->RevertSecurityContext(phContext);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "RevertSecurityContext status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

/* Message Support */

static SECURITY_STATUS SEC_ENTRY winpr_DecryptMessage(PCtxtHandle phContext,
        PSecBufferDesc pMessage,
        ULONG MessageSeqNo, PULONG pfQOP)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->DecryptMessage)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "DecryptMessage status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_EncryptMessage(PCtxtHandle phContext, ULONG fQOP,
        PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->EncryptMessage)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);

	if (status != SEC_E_OK)
	{
		WLog_ERR(TAG, "EncryptMessage status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_MakeSignature(PCtxtHandle phContext, ULONG fQOP,
        PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->MakeSignature)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->MakeSignature(phContext, fQOP, pMessage, MessageSeqNo);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "MakeSignature status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SECURITY_STATUS SEC_ENTRY winpr_VerifySignature(PCtxtHandle phContext,
        PSecBufferDesc pMessage,
        ULONG MessageSeqNo, PULONG pfQOP)
{
	char* Name;
	SECURITY_STATUS status;
	const SecurityFunctionTableA* table;
	Name = (char*) sspi_SecureHandleGetUpperPointer(phContext);

	if (!Name)
		return SEC_E_SECPKG_NOT_FOUND;

	table = sspi_GetSecurityFunctionTableAByNameA(Name);

	if (!table)
		return SEC_E_SECPKG_NOT_FOUND;

	if (!table->VerifySignature)
		return SEC_E_UNSUPPORTED_FUNCTION;

	status = table->VerifySignature(phContext, pMessage, MessageSeqNo, pfQOP);

	if (IsSecurityStatusError(status))
	{
		WLog_WARN(TAG, "VerifySignature status %s [0x%08"PRIX32"]",
		          GetSecurityStatusString(status), status);
	}

	return status;
}

static SecurityFunctionTableA winpr_SecurityFunctionTableA =
{
	1, /* dwVersion */
	winpr_EnumerateSecurityPackagesA, /* EnumerateSecurityPackages */
	winpr_QueryCredentialsAttributesA, /* QueryCredentialsAttributes */
	winpr_AcquireCredentialsHandleA, /* AcquireCredentialsHandle */
	winpr_FreeCredentialsHandle, /* FreeCredentialsHandle */
	NULL, /* Reserved2 */
	winpr_InitializeSecurityContextA, /* InitializeSecurityContext */
	winpr_AcceptSecurityContext, /* AcceptSecurityContext */
	winpr_CompleteAuthToken, /* CompleteAuthToken */
	winpr_DeleteSecurityContext, /* DeleteSecurityContext */
	winpr_ApplyControlToken, /* ApplyControlToken */
	winpr_QueryContextAttributesA, /* QueryContextAttributes */
	winpr_ImpersonateSecurityContext, /* ImpersonateSecurityContext */
	winpr_RevertSecurityContext, /* RevertSecurityContext */
	winpr_MakeSignature, /* MakeSignature */
	winpr_VerifySignature, /* VerifySignature */
	winpr_FreeContextBuffer, /* FreeContextBuffer */
	winpr_QuerySecurityPackageInfoA, /* QuerySecurityPackageInfo */
	NULL, /* Reserved3 */
	NULL, /* Reserved4 */
	winpr_ExportSecurityContext, /* ExportSecurityContext */
	winpr_ImportSecurityContextA, /* ImportSecurityContext */
	NULL, /* AddCredentials */
	NULL, /* Reserved8 */
	winpr_QuerySecurityContextToken, /* QuerySecurityContextToken */
	winpr_EncryptMessage, /* EncryptMessage */
	winpr_DecryptMessage, /* DecryptMessage */
	winpr_SetContextAttributesA, /* SetContextAttributes */
};

static SecurityFunctionTableW winpr_SecurityFunctionTableW =
{
	1, /* dwVersion */
	winpr_EnumerateSecurityPackagesW, /* EnumerateSecurityPackages */
	winpr_QueryCredentialsAttributesW, /* QueryCredentialsAttributes */
	winpr_AcquireCredentialsHandleW, /* AcquireCredentialsHandle */
	winpr_FreeCredentialsHandle, /* FreeCredentialsHandle */
	NULL, /* Reserved2 */
	winpr_InitializeSecurityContextW, /* InitializeSecurityContext */
	winpr_AcceptSecurityContext, /* AcceptSecurityContext */
	winpr_CompleteAuthToken, /* CompleteAuthToken */
	winpr_DeleteSecurityContext, /* DeleteSecurityContext */
	winpr_ApplyControlToken, /* ApplyControlToken */
	winpr_QueryContextAttributesW, /* QueryContextAttributes */
	winpr_ImpersonateSecurityContext, /* ImpersonateSecurityContext */
	winpr_RevertSecurityContext, /* RevertSecurityContext */
	winpr_MakeSignature, /* MakeSignature */
	winpr_VerifySignature, /* VerifySignature */
	winpr_FreeContextBuffer, /* FreeContextBuffer */
	winpr_QuerySecurityPackageInfoW, /* QuerySecurityPackageInfo */
	NULL, /* Reserved3 */
	NULL, /* Reserved4 */
	winpr_ExportSecurityContext, /* ExportSecurityContext */
	winpr_ImportSecurityContextW, /* ImportSecurityContext */
	NULL, /* AddCredentials */
	NULL, /* Reserved8 */
	winpr_QuerySecurityContextToken, /* QuerySecurityContextToken */
	winpr_EncryptMessage, /* EncryptMessage */
	winpr_DecryptMessage, /* DecryptMessage */
	winpr_SetContextAttributesW, /* SetContextAttributes */
};
