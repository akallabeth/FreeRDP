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

#include <gss.h>

#include "kerberos.h"

#include "../sspi.h"
#include "../../log.h"
#define TAG WINPR_TAG("sspi.Kerberos")

struct _KRB_CONTEXT
{
	CtxtHandle context;
	SSPI_CREDENTIALS* credentials;
	SEC_WINNT_AUTH_IDENTITY identity;

	/* GSSAPI */
	UINT32 major_status;
	UINT32 minor_status;
	UINT32 actual_time;
	gss_cred_id_t cred;
	gss_ctx_id_t gss_ctx;
	gss_name_t target_name;
};

static const char* KRB_PACKAGE_NAME = "Kerberos";

const SecPkgInfoA KERBEROS_SecPkgInfoA = {
	0x000F3BBF,                 /* fCapabilities */
	1,                          /* wVersion */
	0x0010,                     /* wRPCID */
	0x0000BB80,                 /* cbMaxToken : 48k bytes maximum for Windows Server 2012 */
	"Kerberos",                 /* Name */
	"Kerberos Security Package" /* Comment */
};

static WCHAR KERBEROS_SecPkgInfoW_Name[] = { 'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', '\0' };

static WCHAR KERBEROS_SecPkgInfoW_Comment[] = { 'K', 'e', 'r', 'b', 'e', 'r', 'o', 's', ' ',
	                                            'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', ' ',
	                                            'P', 'a', 'c', 'k', 'a', 'g', 'e', '\0' };

const SecPkgInfoW KERBEROS_SecPkgInfoW = {
	0x000F3BBF,                  /* fCapabilities */
	1,                           /* wVersion */
	0x0010,                      /* wRPCID */
	0x0000BB80,                  /* cbMaxToken : 48k bytes maximum for Windows Server 2012 */
	KERBEROS_SecPkgInfoW_Name,   /* Name */
	KERBEROS_SecPkgInfoW_Comment /* Comment */
};

static gss_OID_desc g_SSPI_GSS_C_SPNEGO_KRB5 = { 9, (void*)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" };
static gss_OID SSPI_GSS_C_SPNEGO_KRB5 = &g_SSPI_GSS_C_SPNEGO_KRB5;

static BOOL kerberos_SetContextServicePrincipalNameA(KRB_CONTEXT* context,
                                                     SEC_CHAR* ServicePrincipalName);

static const char* calling_error_2_str(OM_uint32 error)
{
	switch (error & 0xFF000000)
	{
		case 0:
			return "";
		case GSS_S_CALL_INACCESSIBLE_READ:
			return "GSS_S_CALL_INACCESSIBLE_READ";
		case GSS_S_CALL_INACCESSIBLE_WRITE:
			return "GSS_S_CALL_INACCESSIBLE_WRITE";
		case GSS_S_CALL_BAD_STRUCTURE:
			return "GSS_S_CALL_BAD_STRUCTURE";
		default:
			return "GSS_UNKNOWN_CALLING_ERROR";
	}
}

static const char* routine_error_2_str(OM_uint32 error)
{
	switch (error & 0xFF0000)
	{
		case 0:
			return "";
		case GSS_S_BAD_MECH:
			return "GSS_S_BAD_MECH";
		case GSS_S_BAD_NAME:
			return "GSS_S_BAD_NAME";
		case GSS_S_BAD_NAMETYPE:
			return "GSS_S_BAD_NAMETYPE";
		case GSS_S_BAD_BINDINGS:
			return "GSS_S_BAD_BINDINGS";
		case GSS_S_BAD_STATUS:
			return "GSS_S_BAD_STATUS";
		case GSS_S_BAD_SIG:
			return "GSS_S_BAD_SIG";
		case GSS_S_NO_CRED:
			return "GSS_S_NO_CRED";
		case GSS_S_NO_CONTEXT:
			return "GSS_S_NO_CONTEXT";
		case GSS_S_DEFECTIVE_TOKEN:
			return "GSS_S_DEFECTIVE_TOKEN";
		case GSS_S_DEFECTIVE_CREDENTIAL:
			return "GSS_S_DEFECTIVE_CREDENTIAL";
		case GSS_S_CREDENTIALS_EXPIRED:
			return "GSS_S_CREDENTIALS_EXPIRED";
		case GSS_S_CONTEXT_EXPIRED:
			return "GSS_S_CONTEXT_EXPIRED";
		case GSS_S_FAILURE:
			return "GSS_S_FAILURE";
		case GSS_S_BAD_QOP:
			return "GSS_S_BAD_QOP";
		case GSS_S_UNAUTHORIZED:
			return "GSS_S_UNAUTHORIZED";
		case GSS_S_UNAVAILABLE:
			return "GSS_S_UNAVAILABLE";
		case GSS_S_DUPLICATE_ELEMENT:
			return "GSS_S_DUPLICATE_ELEMENT";
		case GSS_S_NAME_NOT_MN:
			return "GSS_S_NAME_NOT_MN";
		default:
			return "GSS_UNKNOWN_ROUTINE_ERROR";
	}
}

static const char* supplementary_info_2_str(OM_uint32 error)
{
	switch (error & 0xFFFF)
	{
		case 0:
			return "";
		case GSS_S_CONTINUE_NEEDED:
			return "GSS_S_CONTINUE_NEEDED";
		case GSS_S_DUPLICATE_TOKEN:
			return "GSS_S_DUPLICATE_TOKEN";
		case GSS_S_OLD_TOKEN:
			return "GSS_S_OLD_TOKEN";
		case GSS_S_UNSEQ_TOKEN:
			return "GSS_S_UNSEQ_TOKEN";
		case GSS_S_GAP_TOKEN:
			return "GSS_S_GAP_TOKEN";
		default:
			return "GSS_UNKNOWN_SUPPLIMENTARY_INFO";
	}
}

static char* alloc_printf(const char* fmt, ...)
{
	int rc;
	char* str = NULL;
	va_list ap;
	va_start(ap, fmt);
	rc = vsnprintf_s(NULL, 0, fmt, ap);
	va_end(ap);
	if (rc <= 0)
		return NULL;
	str = (char*)calloc(rc + 2, sizeof(char));
	if (!str)
		return NULL;

	va_start(ap, fmt);
	rc = vsnprintf_s(str, rc + 1, fmt, ap);
	if (rc < 0)
	{
		free(str);
		return NULL;
	}
	va_end(ap);
	return str;
}

#define failure(what, major, minor) \
	failure_(__FILE__, __FUNCTION__, __LINE__, (what), (major), (minor))
static BOOL failure_(const char* file, const char* fkt, size_t line, const char* what,
                     uint32_t major_status, uint32_t minor_status)
{
	static wLog* _log = WLog_Get(TAG);
	if (GSS_ERROR(major_status))
	{
		if (WLog_IsLevelActive(_log, WLOG_ERROR))
			WLog_PrintMessage(_log, WLOG_MESSAGE_TEXT, WLOG_ERROR, line, file, fkt,
			                  "[%s] failed with [%s|%s|%s] [0x%08" PRIu32 "] [minor=0x%08" PRIu32,
			                  what, calling_error_2_str(major_status),
			                  routine_error_2_str(major_status),
			                  supplementary_info_2_str(major_status), major_status, minor_status);
		return TRUE;
	}
	if (WLog_IsLevelActive(_log, WLOG_DEBUG))
		WLog_PrintMessage(_log, WLOG_MESSAGE_TEXT, WLOG_DEBUG, line, file, fkt, "[%s] succeeded",
		                  what);

	return FALSE;
}

static KRB_CONTEXT* kerberos_ContextNew(void)
{
	KRB_CONTEXT* context;
	context = (KRB_CONTEXT*)calloc(1, sizeof(KRB_CONTEXT));

	if (!context)
		return NULL;

	context->minor_status = 0;
	context->major_status = 0;
	context->gss_ctx = GSS_C_NO_CONTEXT;
	context->cred = GSS_C_NO_CREDENTIAL;
	return context;
}

static void kerberos_ContextFree(KRB_CONTEXT* context)
{
	UINT32 minor_status, major_status;

	if (!context)
		return;

	kerberos_SetContextServicePrincipalNameA(context, NULL);

	if (context->gss_ctx)
	{
		major_status = gss_delete_sec_context(&minor_status, &context->gss_ctx, GSS_C_NO_BUFFER);
		failure("gss_delete_sec_context", major_status, minor_status);
		context->gss_ctx = GSS_C_NO_CONTEXT;
	}

	free(context);
}

static SECURITY_STATUS SEC_ENTRY kerberos_AcquireCredentialsHandleW(
    SEC_WCHAR* pszPrincipal, SEC_WCHAR* pszPackage, ULONG fCredentialUse, void* pvLogonID,
    void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

static SECURITY_STATUS SEC_ENTRY kerberos_AcquireCredentialsHandleA(
    SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage, ULONG fCredentialUse, void* pvLogonID,
    void* pAuthData, SEC_GET_KEY_FN pGetKeyFn, void* pvGetKeyArgument, PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
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

	WLog_ERR(TAG, "[%s]: TODO: Implement ulAttribute=%08" PRIx32, __FUNCTION__, ulAttribute);
	return SEC_E_UNSUPPORTED_FUNCTION;
}

static SECURITY_STATUS SEC_ENTRY kerberos_QueryCredentialsAttributesA(PCredHandle phCredential,
                                                                      ULONG ulAttribute,
                                                                      void* pBuffer)
{
	return kerberos_QueryCredentialsAttributesW(phCredential, ulAttribute, pBuffer);
}

static SECURITY_STATUS SEC_ENTRY kerberos_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName, ULONG fContextReq,
    ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput, ULONG* pfContextAttr, PTimeStamp ptsExpiry)
{
	WLog_ERR(TAG, "[%s]: TODO: Implement", __FUNCTION__);
	return SEC_E_UNSUPPORTED_FUNCTION;
}

static gss_name_t kerberos_get_service_name(const SEC_CHAR* ServicePrincipalName)
{
	char* p;
	UINT32 major_status;
	UINT32 minor_status;
	gss_name_t target_name;
	gss_buffer_desc name_buffer;

	if (!ServicePrincipalName)
		return NULL;

	/* GSSAPI expects a SPN of type <service>@FQDN, let's construct it */
	p = strchr(ServicePrincipalName, '/');
	if (!p)
		return NULL;
	p++;

	name_buffer.value = p;
	name_buffer.length = strlen(p) + 1;
	major_status =
	    gss_import_name(&minor_status, &name_buffer, GSS_C_NT_HOSTBASED_SERVICE, &target_name);

	if (GSS_ERROR(major_status))
	{
		WLog_ERR(TAG, "error: gss_import_name failed");
		return NULL;
	}

	return target_name;
}

static BOOL kerberos_SetContextServicePrincipalNameA(KRB_CONTEXT* context,
                                                     SEC_CHAR* ServicePrincipalName)
{
	if (context->target_name)
	{
		OM_uint32 minor_status;
		gss_release_name(&minor_status, &context->target_name);
		context->target_name = NULL;
	}
	if (ServicePrincipalName)
	{
		gss_name_t targetName = kerberos_get_service_name(ServicePrincipalName);
		context->target_name = targetName;
	}
	return context->target_name != NULL;
}

static BOOL kerberos_TestGetCredentials(const SEC_CHAR* targetName)
{
	OM_uint32 minStat;
	gss_cred_id_t cred;
	OM_uint32 majStat;
	OM_uint32 ignored;
	gss_name_t serviceName = kerberos_get_service_name(targetName);
	if (!serviceName)
		return FALSE;

	majStat = gss_acquire_cred(&minStat, serviceName, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
	                           GSS_C_INITIATE, &cred, NULL, NULL);

	gss_release_name(&ignored, &serviceName);
	gss_release_cred(&ignored, &cred);

	if (majStat != GSS_S_COMPLETE)
	{
		return FALSE;
	}
	return TRUE;
}

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
	gss_OID desired_mech;
	UINT32 actual_services;
	input_tok.length = 0;
	output_tok.length = 0;
	desired_mech = SSPI_GSS_C_SPNEGO_KRB5;
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
		sspi_SecureHandleSetUpperPointer(phNewContext, (void*)KRB_PACKAGE_NAME);
	}

	if (!pInput)
	{
		context->major_status = gss_init_sec_context(
		    &(context->minor_status), context->cred, &(context->gss_ctx), context->target_name,
		    desired_mech, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, GSS_C_INDEFINITE,
		    GSS_C_NO_CHANNEL_BINDINGS, &input_tok, &actual_mech, &output_tok, &actual_services,
		    &(context->actual_time));

		if (GSS_ERROR(context->major_status))
		{
			/* GSSAPI failed because we do not have credentials */
			if (context->major_status & GSS_S_NO_CRED)
				return SEC_E_NO_CREDENTIALS;
		}

		if (context->major_status & GSS_S_CONTINUE_NEEDED)
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
				gss_release_buffer(&(context->minor_status), &output_tok);
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
		context->major_status = gss_init_sec_context(
		    &(context->minor_status), context->cred, &(context->gss_ctx), context->target_name,
		    desired_mech, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, GSS_C_INDEFINITE,
		    GSS_C_NO_CHANNEL_BINDINGS, &input_tok, &actual_mech, &output_tok, &actual_services,
		    &(context->actual_time));

		if (GSS_ERROR(context->major_status))
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

	return SEC_E_INTERNAL_ERROR;
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
	return SEC_E_UNSUPPORTED_FUNCTION;
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

	WLog_ERR(TAG, "[%s]: TODO: Implement ulAttribute=%08" PRIx32, __FUNCTION__, ulAttribute);
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
	return SEC_E_UNSUPPORTED_FUNCTION;
}

static SECURITY_STATUS SEC_ENTRY kerberos_VerifySignature(PCtxtHandle phContext,
                                                          PSecBufferDesc pMessage,
                                                          ULONG MessageSeqNo, ULONG* pfQOP)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
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
