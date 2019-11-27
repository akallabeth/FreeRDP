/**
 * FreeRDP: A Remote Desktop Protocol Client
 * Kerberos Auth Protocol
 *
 * Copyright 2015 ANSSI, Author Thomas Calderon
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <winpr/registry.h>

#include "kerberos.h"

#include "../sspi.h"
#include "../../log.h"
#define TAG WINPR_TAG("sspi.Kerberos")

#include <winpr/windows.h>

#include <gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define RUN_WITH_LOG(status, fkt, ...)                        \
	do                                                        \
	{                                                         \
		OM_uint32 minor_status;                               \
		OM_uint32 major_status;                               \
                                                              \
		major_status = fkt(&minor_status, __VA_ARGS__);       \
		if (GSS_ERROR(major_status))                          \
			gss_log_status(major_status, minor_status, #fkt); \
		(status) = major_status;                              \
	} while (0)

typedef struct _KRB_CONTEXT KRB_CONTEXT;

struct _KRB_CONTEXT
{
	CtxtHandle context;
	SSPI_CREDENTIALS* credentials;
	SEC_WINNT_AUTH_IDENTITY identity;

	/* GSSAPI */
	UINT32 actual_time;
	gss_cred_id_t cred;
	gss_ctx_id_t gss_ctx;
	gss_name_t target_name;
};

static CHAR S_KERBEROS_PACKAGE_NAME_A[] = KERBEROS_SSP_NAME_A;
static WCHAR S_KERBEROS_PACKAGE_NAME_W[] = KERBEROS_SSP_NAME_W;

const SecPkgInfoA KERBEROS_SecPkgInfoA = {
	0x000F3BBF,                 /* fCapabilities */
	1,                          /* wVersion */
	0x0010,                     /* wRPCID */
	0x0000BB80,                 /* cbMaxToken : 48k bytes maximum for Windows Server 2012 */
	"Kerberos",                 /* Name */
	"Kerberos Security Package" /* Comment */
};

static WCHAR KERBEROS_SecPkgInfoW_Comment[] = { 'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', ' ',
	                                            'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', ' ',
	                                            'P', 'a', 'c', 'k', 'a', 'g', 'e', '\0' };

const SecPkgInfoW KERBEROS_SecPkgInfoW = {
	0x000F3BBF,                  /* fCapabilities */
	1,                           /* wVersion */
	0x0010,                      /* wRPCID */
	0x0000BB80,                  /* cbMaxToken : 48k bytes maximum for Windows Server 2012 */
	S_KERBEROS_PACKAGE_NAME_W,   /* Name */
	KERBEROS_SecPkgInfoW_Comment /* Comment */
};

static char* gss_status_str(int type, OM_uint32 gss_status)
{
	size_t len = 0;
	char* rc = NULL;
	OM_uint32 message_context = 0;

	do
	{
		char* tmp;
		OM_uint32 min_status;
		gss_buffer_desc status_string;
		size_t pos = len;
		const OM_uint32 status = gss_display_status(&min_status, gss_status, type, GSS_C_NO_OID,
		                                            &message_context, &status_string);
		if (GSS_ERROR(status))
		{
			free(rc);
			gss_release_buffer(&min_status, &status_string);
			return NULL;
		}

		len += status_string.length + 1;
		tmp = realloc(rc, len);
		if (!tmp)
		{
			free(rc);
			gss_release_buffer(&min_status, &status_string);
			return NULL;
		}
		rc = tmp;
		rc[pos] = '\0';
		strncat(rc, status_string.value, len - 1);

		gss_release_buffer(&min_status, &status_string);

	} while (message_context != 0);

	return rc;
}

static char* format_message(const char* msg, va_list ap)
{

	int rc = 0;
	size_t size = 0;
	char* buffer = NULL;
	while (size == 0)
	{
		if ((size_t)rc > size)
		{
			size = (size_t)rc + 1;
			char* tmp = realloc(buffer, size);
			if (!tmp)
			{
				free(buffer);
				return NULL;
			}
			buffer = tmp;
		}

		rc = vsnprintf(buffer, size, msg, ap);
		if (rc < 0)
		{
			free(buffer);
			return NULL;
		}
	}
	return buffer;
}

static void gss_log_status(OM_uint32 major_status, OM_uint32 minor_status, const char* fmt, ...)
{
	char* msg;
	char* mas = gss_status_str(GSS_C_GSS_CODE, major_status);
	char* mis = gss_status_str(GSS_C_MECH_CODE, minor_status);
	va_list ap;
	va_start(ap, fmt);
	msg = format_message(fmt, ap);
	va_end(ap);

	WLog_ERR(TAG, "[%s] %s: %s", msg, mas, mis);
	free(msg);
	free(mas);
	free(mis);
}

static KRB_CONTEXT* kerberos_ContextNew(void)
{
	KRB_CONTEXT* context;
	context = (KRB_CONTEXT*)calloc(1, sizeof(KRB_CONTEXT));

	if (!context)
		return NULL;

	context->gss_ctx = GSS_C_NO_CONTEXT;
	context->cred = GSS_C_NO_CREDENTIAL;
	return context;
}

static void kerberos_ContextFree(KRB_CONTEXT* context)
{
	UINT32 minor_status;

	if (!context)
		return;

	if (context->target_name)
	{
		gss_release_name(&minor_status, &context->target_name);
		context->target_name = NULL;
	}

	if (context->gss_ctx)
	{
		gss_delete_sec_context(&minor_status, &context->gss_ctx, GSS_C_NO_BUFFER);
		context->gss_ctx = GSS_C_NO_CONTEXT;
	}

	free(context);
}

static SECURITY_STATUS SEC_ENTRY kerberos_AcquireCredentialsHandleW(
    SEC_WCHAR* pszPrincipal, SEC_WCHAR* pszPackage, ULONG fCredentialUse, void* pvLogonID,
    void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_AcquireCredentialsHandleA(
    SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage, ULONG fCredentialUse, void* pvLogonID,
    void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_FreeCredentialsHandle(PCredHandle phCredential)
{
	SSPI_CREDENTIALS* credentials;

	if (!phCredential)
		return SEC_E_INVALID_HANDLE;

	credentials = (SSPI_CREDENTIALS*)sspi_SecureHandleGetLowerPointer(phCredential);

	if (!credentials)
		return SEC_E_INVALID_HANDLE;

	sspi_CredentialsFree(credentials);
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_QueryCredentialsAttributesW(PCredHandle phCredential,
                                                                      ULONG ulAttribute,
                                                                      void* pBuffer)
{
	if (ulAttribute == SECPKG_CRED_ATTR_NAMES)
	{
		return SEC_E_OK;
	}

	return SEC_E_UNSUPPORTED_FUNCTION;
}

static SECURITY_STATUS SEC_ENTRY kerberos_QueryCredentialsAttributesA(PCredHandle phCredential,
                                                                      ULONG ulAttribute,
                                                                      void* pBuffer)
{
	return kerberos_QueryCredentialsAttributesW(phCredential, ulAttribute, pBuffer);
}

static BOOL kerberos_SetContextServicePrincipalNameA(KRB_CONTEXT* context,
                                                     const SEC_CHAR* ServicePrincipalName)
{
	BOOL rc = FALSE;
	char* p;
	const SEC_CHAR prefix[8] = "TERMSRV/";
	OM_uint32 major_status = 0;
	char* gss_name = NULL;
	gss_buffer_desc name_buffer;

	if (!ServicePrincipalName)
	{
		context->target_name = NULL;
		return TRUE;
	}

	if (_strnicmp(prefix, ServicePrincipalName, ARRAYSIZE(prefix)) != 0)
	{
		context->target_name = NULL;
		return FALSE;
	}

	/* GSSAPI expects a SPN of type <service>@FQDN, let's construct it */
	gss_name = _strdup(ServicePrincipalName);

	if (!gss_name)
		return FALSE;

	p = strchr(gss_name, '/');

	if (p)
		*p = '@';

	name_buffer.value = gss_name;
	name_buffer.length = strlen(gss_name) + 1;
	RUN_WITH_LOG(major_status, gss_import_name, &name_buffer, GSS_C_NT_HOSTBASED_SERVICE,
	             &(context->target_name));

	rc = !GSS_ERROR(major_status);
	RUN_WITH_LOG(major_status, gss_release_buffer, &name_buffer);

	return rc;
}

#ifdef WITH_GSSAPI

static gss_cred_id_t init_creds(LPCWSTR username, size_t username_len, LPCWSTR password,
                                size_t password_len)
{
	char* lusername = NULL;
	char* lpassword = NULL;
	int status = 0;
	OM_uint32 maj_stat;
	OM_uint32 min_stat;
	gss_name_t gss_username = GSS_C_NO_NAME;
	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
	// gss_OID_set_desc mechs = { 1,  &gss_spnego_mechanism_oid_desc};
	gss_OID_set_desc* mechsp = GSS_C_NO_OID_SET;

	status = ConvertFromUnicode(CP_UTF8, 0, username, username_len, &lusername, 0, NULL, NULL);

	if (status <= 0)
	{
		WLog_ERR(TAG, "Failed to convert username");
		goto cleanup;
	}

	if (lusername != NULL)
	{
		gss_buffer_desc send_tok;

		send_tok.value = lusername;
		send_tok.length = strlen(lusername);

		RUN_WITH_LOG(maj_stat, gss_import_name, &send_tok, (gss_OID)gss_nt_user_name,
		             &gss_username);
		if (maj_stat != GSS_S_COMPLETE)
		{
			goto cleanup;
		}
	}

	status = ConvertFromUnicode(CP_UTF8, 0, password, password_len, &lpassword, 0, NULL, NULL);

	if (status <= 0)
	{
		WLog_ERR(TAG, "Failed to convert password");
		goto cleanup;
	}

	if (lpassword != NULL)
	{
		gss_buffer_desc pwbuf;

		pwbuf.value = lpassword;
		pwbuf.length = strlen(lpassword);

		RUN_WITH_LOG(maj_stat, gss_acquire_cred_with_password, gss_username, &pwbuf, 0, mechsp,
		             GSS_C_INITIATE, &cred, NULL, NULL);
		gss_release_buffer(&min_stat, &pwbuf);
	}
	else if (gss_username != GSS_C_NO_NAME)
	{
		RUN_WITH_LOG(maj_stat, gss_acquire_cred, gss_username, 0, mechsp, GSS_C_INITIATE, &cred,
		             NULL, NULL);
	}
	else
		maj_stat = GSS_S_COMPLETE;

cleanup:
	gss_release_name(&min_stat, &gss_username);

	return cred;
}
#endif

static SECURITY_STATUS SEC_ENTRY kerberos_InitializeSecurityContextA(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR* pszTargetName, ULONG fContextReq,
    ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG* pfContextAttr, PTimeStamp ptsExpiry)
{
	KRB_CONTEXT* context;
	SSPI_CREDENTIALS* credentials;
	PSecBuffer input_buffer = NULL;
	PSecBuffer output_buffer = NULL;
	gss_buffer_desc input_tok = { 0 };
	gss_buffer_desc output_tok = { 0 };
	gss_OID actual_mech;
	char* mech_str = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\0";
	gss_OID_desc desired_mech = { 9, mech_str };
	OM_uint32 major_status = 0, minor_status;
	UINT32 actual_services;

	WINPR_UNUSED(Reserved1);
	WINPR_UNUSED(Reserved2);

	input_tok.length = 0;
	output_tok.length = 0;

	context = (KRB_CONTEXT*)sspi_SecureHandleGetLowerPointer(phContext);

	if (!context)
	{
		context = kerberos_ContextNew();

		if (!context)
			return SEC_E_INSUFFICIENT_MEMORY;

		credentials = (SSPI_CREDENTIALS*)sspi_SecureHandleGetLowerPointer(phCredential);
		context->credentials = credentials;

		if (!kerberos_SetContextServicePrincipalNameA(context, pszTargetName))
		{
			kerberos_ContextFree(context);
			return SEC_E_INTERNAL_ERROR;
		}

		sspi_SecureHandleSetLowerPointer(phNewContext, context);
		sspi_SecureHandleSetUpperPointer(phNewContext, S_KERBEROS_PACKAGE_NAME_A);
	}

	if (!pInput)
	{
#if defined(WITH_GSSAPI)
		context->cred = init_creds(
		    context->credentials->identity.User, context->credentials->identity.UserLength,
		    context->credentials->identity.Password, context->credentials->identity.PasswordLength);

		RUN_WITH_LOG(major_status, gss_init_sec_context, context->cred, &(context->gss_ctx),
		             context->target_name, &desired_mech, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG,
		             GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &input_tok, &actual_mech,
		             &output_tok, &actual_services, &(context->actual_time));

		if (GSS_ERROR(major_status))
		{
			/* GSSAPI failed because we do not have credentials */
			if (major_status & GSS_S_NO_CRED)
			{
				context->cred = init_creds(context->credentials->identity.User,
				                           context->credentials->identity.UserLength,
				                           context->credentials->identity.Password,
				                           context->credentials->identity.PasswordLength);

				WLog_INFO(TAG, "Authenticated to Kerberos v5 via login/password");
				/* retry GSSAPI call */
				RUN_WITH_LOG(major_status, gss_init_sec_context, context->cred, &(context->gss_ctx),
				             context->target_name, &desired_mech,
				             GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, GSS_C_INDEFINITE,
				             GSS_C_NO_CHANNEL_BINDINGS, &input_tok, &actual_mech, &output_tok,
				             &actual_services, &(context->actual_time));

				if (GSS_ERROR(major_status))
				{
					/* We can't use Kerberos */
					WLog_ERR(TAG, "Init GSS security context failed : can't use Kerberos");
					return SEC_E_NO_CREDENTIALS;
				}
			}
			else
				return SEC_E_NO_CONTEXT;
		}

#endif

		if (major_status & GSS_S_CONTINUE_NEEDED)
		{
			if (output_tok.length != 0)
			{
				if (!pOutput)
					return SEC_E_INVALID_TOKEN;

				if (pOutput->cBuffers < 1)
					return SEC_E_INVALID_TOKEN;

				output_buffer = sspi_FindSecBuffer(pOutput, SECBUFFER_TOKEN);

				if (!output_buffer)
					return SEC_E_INVALID_TOKEN;

				if (output_buffer->cbBuffer < 1)
					return SEC_E_INVALID_TOKEN;

				CopyMemory(output_buffer->pvBuffer, output_tok.value, output_tok.length);
				output_buffer->cbBuffer = output_tok.length;
				gss_release_buffer(&(minor_status), &output_tok);
				return SEC_I_CONTINUE_NEEDED;
			}
		}
	}
	else
	{
		input_buffer = sspi_FindSecBuffer(pInput, SECBUFFER_TOKEN);

		if (!input_buffer)
			return SEC_E_INVALID_TOKEN;

		if (input_buffer->cbBuffer < 1)
			return SEC_E_INVALID_TOKEN;

		input_tok.value = input_buffer->pvBuffer;
		input_tok.length = input_buffer->cbBuffer;
		major_status = gss_init_sec_context(&(minor_status), context->cred, &(context->gss_ctx),
		                                    context->target_name, &desired_mech,
		                                    GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, GSS_C_INDEFINITE,
		                                    GSS_C_NO_CHANNEL_BINDINGS, &input_tok, &actual_mech,
		                                    &output_tok, &actual_services, &(context->actual_time));

		if (GSS_ERROR(major_status))
			return SEC_E_INTERNAL_ERROR;

		if (output_tok.length == 0)
		{
			/* Free output_buffer to detect second call in NLA */
			output_buffer = sspi_FindSecBuffer(pOutput, SECBUFFER_TOKEN);
			sspi_SecBufferFree(output_buffer);
			return SEC_E_OK;
		}
		else
		{
			return SEC_E_INTERNAL_ERROR;
		}
	}

	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName, ULONG fContextReq,
    ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG* pfContextAttr, PTimeStamp ptsExpiry)
{
	SECURITY_STATUS status;
	SEC_CHAR* pszTargetNameUtf = NULL;

	ConvertFromUnicode(CP_UTF8, 0, pszTargetName, -1, &pszTargetNameUtf, 0, NULL, NULL);
	status = kerberos_InitializeSecurityContextA(
	    phCredential, phContext, pszTargetNameUtf, fContextReq, Reserved1, TargetDataRep, pInput,
	    Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
	free(pszTargetNameUtf);
	return status;
}

static SECURITY_STATUS SEC_ENTRY kerberos_DeleteSecurityContext(PCtxtHandle phContext)
{
	KRB_CONTEXT* context;
	context = (KRB_CONTEXT*)sspi_SecureHandleGetLowerPointer(phContext);

	if (!context)
		return SEC_E_INVALID_HANDLE;

	kerberos_ContextFree(context);
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_QueryContextAttributesW(PCtxtHandle phContext,
                                                                  ULONG ulAttribute, void* pBuffer)
{
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_QueryContextAttributesA(PCtxtHandle phContext,
                                                                  ULONG ulAttribute, void* pBuffer)
{
	if (!phContext)
		return SEC_E_INVALID_HANDLE;

	if (!pBuffer)
		return SEC_E_INSUFFICIENT_MEMORY;

	if (ulAttribute == SECPKG_ATTR_SIZES)
	{
		SecPkgContext_Sizes* ContextSizes = (SecPkgContext_Sizes*)pBuffer;
		/* The MaxTokenSize by default is 12,000 bytes. This has been the default value
		 * since Windows 2000 SP2 and still remains in Windows 7 and Windows 2008 R2.
		 *  For Windows Server 2012, the default value of the MaxTokenSize registry
		 *  entry is 48,000 bytes.*/
		ContextSizes->cbMaxToken = KERBEROS_SecPkgInfoA.cbMaxToken;
		ContextSizes->cbMaxSignature = 0; /* means verify not supported */
		ContextSizes->cbBlockSize = 0;    /* padding not used */
		ContextSizes->cbSecurityTrailer =
		    60; /* gss_wrap adds additional 60 bytes for encrypt message */
		return SEC_E_OK;
	}

	return SEC_E_UNSUPPORTED_FUNCTION;
}

static SECURITY_STATUS SEC_ENTRY kerberos_EncryptMessage(PCtxtHandle phContext, ULONG fQOP,
                                                         PSecBufferDesc pMessage,
                                                         ULONG MessageSeqNo)
{
	int index;
	int conf_state;
	UINT32 major_status;
	UINT32 minor_status;
	KRB_CONTEXT* context;
	gss_buffer_desc input;
	gss_buffer_desc output;
	PSecBuffer data_buffer = NULL;
	context = (KRB_CONTEXT*)sspi_SecureHandleGetLowerPointer(phContext);

	if (!context)
		return SEC_E_INVALID_HANDLE;

	for (index = 0; index < (int)pMessage->cBuffers; index++)
	{
		if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
			data_buffer = &pMessage->pBuffers[index];
	}

	if (!data_buffer)
		return SEC_E_INVALID_TOKEN;

	input.value = data_buffer->pvBuffer;
	input.length = data_buffer->cbBuffer;
	major_status = gss_wrap(&minor_status, context->gss_ctx, TRUE, GSS_C_QOP_DEFAULT, &input,
	                        &conf_state, &output);

	if (GSS_ERROR(major_status))
		return SEC_E_INTERNAL_ERROR;

	if (conf_state == 0)
	{
		WLog_ERR(TAG, "error: gss_wrap confidentiality was not applied");
		gss_release_buffer(&minor_status, &output);
		return SEC_E_INTERNAL_ERROR;
	}

	CopyMemory(data_buffer->pvBuffer, output.value, output.length);
	gss_release_buffer(&minor_status, &output);
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_DecryptMessage(PCtxtHandle phContext,
                                                         PSecBufferDesc pMessage,
                                                         ULONG MessageSeqNo, ULONG* pfQOP)
{
	int index;
	int conf_state;
	UINT32 major_status;
	UINT32 minor_status;
	KRB_CONTEXT* context;
	gss_buffer_desc input_data;
	gss_buffer_desc output;
	PSecBuffer data_buffer_to_unwrap = NULL;
	context = (KRB_CONTEXT*)sspi_SecureHandleGetLowerPointer(phContext);

	if (!context)
		return SEC_E_INVALID_HANDLE;

	for (index = 0; index < (int)pMessage->cBuffers; index++)
	{
		if (pMessage->pBuffers[index].BufferType == SECBUFFER_DATA)
			data_buffer_to_unwrap = &pMessage->pBuffers[index];
	}

	if (!data_buffer_to_unwrap)
		return SEC_E_INVALID_TOKEN;

	/* unwrap encrypted TLS key AND its signature */
	input_data.value = data_buffer_to_unwrap->pvBuffer;
	input_data.length = data_buffer_to_unwrap->cbBuffer;
	major_status =
	    gss_unwrap(&minor_status, context->gss_ctx, &input_data, &output, &conf_state, NULL);

	if (GSS_ERROR(major_status))
		return SEC_E_INTERNAL_ERROR;

	if (conf_state == 0)
	{
		WLog_ERR(TAG, "error: gss_unwrap confidentiality was not applied");
		gss_release_buffer(&minor_status, &output);
		return SEC_E_INTERNAL_ERROR;
	}

	CopyMemory(data_buffer_to_unwrap->pvBuffer, output.value, output.length);
	gss_release_buffer(&minor_status, &output);
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_MakeSignature(PCtxtHandle phContext, ULONG fQOP,
                                                        PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	return SEC_E_OK;
}

static SECURITY_STATUS SEC_ENTRY kerberos_VerifySignature(PCtxtHandle phContext,
                                                          PSecBufferDesc pMessage,
                                                          ULONG MessageSeqNo, ULONG* pfQOP)
{
	return SEC_E_OK;
}

const SecurityFunctionTableA KERBEROS_SecurityFunctionTableA = {
	1,                                    /* dwVersion */
	NULL,                                 /* EnumerateSecurityPackages */
	kerberos_QueryCredentialsAttributesA, /* QueryCredentialsAttributes */
	kerberos_AcquireCredentialsHandleA,   /* AcquireCredentialsHandle */
	kerberos_FreeCredentialsHandle,       /* FreeCredentialsHandle */
	NULL,                                 /* Reserved2 */
	kerberos_InitializeSecurityContextA,  /* InitializeSecurityContext */
	NULL,                                 /* AcceptSecurityContext */
	NULL,                                 /* CompleteAuthToken */
	kerberos_DeleteSecurityContext,       /* DeleteSecurityContext */
	NULL,                                 /* ApplyControlToken */
	kerberos_QueryContextAttributesA,     /* QueryContextAttributes */
	NULL,                                 /* ImpersonateSecurityContext */
	NULL,                                 /* RevertSecurityContext */
	kerberos_MakeSignature,               /* MakeSignature */
	kerberos_VerifySignature,             /* VerifySignature */
	NULL,                                 /* FreeContextBuffer */
	NULL,                                 /* QuerySecurityPackageInfo */
	NULL,                                 /* Reserved3 */
	NULL,                                 /* Reserved4 */
	NULL,                                 /* ExportSecurityContext */
	NULL,                                 /* ImportSecurityContext */
	NULL,                                 /* AddCredentials */
	NULL,                                 /* Reserved8 */
	NULL,                                 /* QuerySecurityContextToken */
	kerberos_EncryptMessage,              /* EncryptMessage */
	kerberos_DecryptMessage,              /* DecryptMessage */
	NULL,                                 /* SetContextAttributes */
};

const SecurityFunctionTableW KERBEROS_SecurityFunctionTableW = {
	1,                                    /* dwVersion */
	NULL,                                 /* EnumerateSecurityPackages */
	kerberos_QueryCredentialsAttributesW, /* QueryCredentialsAttributes */
	kerberos_AcquireCredentialsHandleW,   /* AcquireCredentialsHandle */
	kerberos_FreeCredentialsHandle,       /* FreeCredentialsHandle */
	NULL,                                 /* Reserved2 */
	kerberos_InitializeSecurityContextW,  /* InitializeSecurityContext */
	NULL,                                 /* AcceptSecurityContext */
	NULL,                                 /* CompleteAuthToken */
	kerberos_DeleteSecurityContext,       /* DeleteSecurityContext */
	NULL,                                 /* ApplyControlToken */
	kerberos_QueryContextAttributesW,     /* QueryContextAttributes */
	NULL,                                 /* ImpersonateSecurityContext */
	NULL,                                 /* RevertSecurityContext */
	kerberos_MakeSignature,               /* MakeSignature */
	kerberos_VerifySignature,             /* VerifySignature */
	NULL,                                 /* FreeContextBuffer */
	NULL,                                 /* QuerySecurityPackageInfo */
	NULL,                                 /* Reserved3 */
	NULL,                                 /* Reserved4 */
	NULL,                                 /* ExportSecurityContext */
	NULL,                                 /* ImportSecurityContext */
	NULL,                                 /* AddCredentials */
	NULL,                                 /* Reserved8 */
	NULL,                                 /* QuerySecurityContextToken */
	kerberos_EncryptMessage,              /* EncryptMessage */
	kerberos_DecryptMessage,              /* DecryptMessage */
	NULL,                                 /* SetContextAttributes */
};
