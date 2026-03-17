/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Terminal Server Gateway (utils)
 *
 * Copyright 2021 Armin Novak <armin.novak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
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

#include "settings.h"

#include <winpr/assert.h>

#include <freerdp/freerdp.h>
#include <freerdp/channels/cliprdr.h>
#include <freerdp/channels/rdpdr.h>

#include <freerdp/log.h>
#define TAG FREERDP_TAG("core.gateway.utils")

#include "utils.h"

#include "../core/rdp.h"

BOOL utils_str_copy(const char* value, char** dst)
{
	WINPR_ASSERT(dst);

	free(*dst);
	*dst = nullptr;
	if (!value)
		return TRUE;

	(*dst) = _strdup(value);
	return (*dst) != nullptr;
}

static BOOL utils_settings_str_copy(rdpSettings* settings, FreeRDP_Settings_Keys_String src,
                                    FreeRDP_Settings_Keys_String dst)
{
	const char* str = freerdp_settings_get_string(settings, src);
	return freerdp_settings_set_string(settings, dst, str);
}

static BOOL utils_settings_str_empty(const rdpSettings* settings, FreeRDP_Settings_Keys_String key)
{
	const char* str = freerdp_settings_get_string(settings, key);
	return utils_str_is_empty(str);
}

static BOOL utils_copy_smartcard_settings(const rdpSettings* settings, rdpSettings* origSettings)
{
	const SSIZE_T keys[] = { FreeRDP_SmartcardLogon, FreeRDP_PasswordIsSmartcardPin,
		                     FreeRDP_ReaderName, FreeRDP_CspName, FreeRDP_ContainerName };

	for (size_t x = 0; x < ARRAYSIZE(keys); x++)
	{
		const SSIZE_T key = keys[x];
		if (!freerdp_settings_copy_item(origSettings, settings, key))
			return FALSE;
	}

	return TRUE;
}

static auth_status utils_try_gw_auth(freerdp* instance, rdp_auth_reason reason)
{
	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);

	rdpSettings* settings = instance->context->settings;
	WINPR_ASSERT(settings);

	if (!instance->GatewayAuthenticate && !instance->AuthenticateEx)
		return AUTH_NO_CREDENTIALS;

	auth_status ret = AUTH_CANCELLED;
	const char* CUsername = freerdp_settings_get_string(settings, FreeRDP_GatewayUsername);
	const char* CDomain = freerdp_settings_get_string(settings, FreeRDP_GatewayDomain);
	const char* CPassword = freerdp_settings_get_string(settings, FreeRDP_GatewayPassword);

	char* GatewayUsername = nullptr;
	char* GatewayDomain = nullptr;
	char* GatewayPassword = nullptr;
	if (CUsername)
		GatewayUsername = _strdup(CUsername);
	if (CDomain)
		GatewayDomain = _strdup(CDomain);
	if (CPassword)
		GatewayPassword = _strdup(CPassword);

	if (!instance->GatewayAuthenticate)
	{
		const BOOL proceed = instance->AuthenticateEx(instance, &GatewayUsername, &GatewayPassword,
		                                              &GatewayDomain, reason);
		if (!proceed)
			goto fail;
	}
	else
	{
		const BOOL proceed = instance->GatewayAuthenticate(instance, &GatewayUsername,
		                                                   &GatewayPassword, &GatewayDomain);
		if (!proceed)
			goto fail;
	}

	if (utils_str_is_empty(GatewayUsername) || utils_str_is_empty(GatewayPassword))
	{
		ret = AUTH_NO_CREDENTIALS;
		goto fail;
	}

	if (!freerdp_settings_set_string(settings, FreeRDP_GatewayUsername, GatewayUsername))
		goto fail;
	if (!freerdp_settings_set_string(settings, FreeRDP_GatewayDomain, GatewayDomain))
		goto fail;
	if (!freerdp_settings_set_string(settings, FreeRDP_GatewayPassword, GatewayPassword))
		goto fail;
	ret = AUTH_SUCCESS;

fail:
	free(GatewayUsername);
	free(GatewayDomain);
	free(GatewayPassword);
	return ret;
}

auth_status utils_authenticate_gateway(freerdp* instance, rdp_auth_reason reason)
{
	rdpSettings* settings = nullptr;
	rdpSettings* origSettings = nullptr;
	BOOL prompt = FALSE;
	BOOL proceed = 0;

	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);
	WINPR_ASSERT(instance->context->settings);
	WINPR_ASSERT(instance->context->rdp);
	WINPR_ASSERT(instance->context->rdp->originalSettings);

	settings = instance->context->settings;
	origSettings = instance->context->rdp->originalSettings;

	if (freerdp_shall_disconnect_context(instance->context))
		return AUTH_FAILED;

	if (utils_str_is_empty(freerdp_settings_get_string(settings, FreeRDP_GatewayPassword)))
		prompt = TRUE;
	if (utils_str_is_empty(freerdp_settings_get_string(settings, FreeRDP_GatewayUsername)))
		prompt = TRUE;

	if (!prompt)
	{
		if (!utils_sync_credentials(settings, FALSE))
			return AUTH_FAILED;
		return AUTH_SKIP;
	}

	auth_status rc = utils_try_gw_auth(instance, reason);
	switch (rc)
	{
		case AUTH_SKIP:
		case AUTH_SUCCESS:
			break;
		default:
			return rc;
	}

	if (!utils_sync_credentials(settings, FALSE))
		return AUTH_FAILED;

	/* update original settings with provided user credentials */
	if (!utils_settings_str_copy(settings, FreeRDP_GatewayUsername, FreeRDP_GatewayUsername))
		return AUTH_FAILED;
	if (!utils_settings_str_copy(settings, FreeRDP_GatewayDomain, FreeRDP_GatewayDomain))
		return AUTH_FAILED;
	if (!utils_settings_str_copy(settings, FreeRDP_GatewayPassword, FreeRDP_GatewayPassword))
		return AUTH_FAILED;
	if (!utils_sync_credentials(origSettings, FALSE))
		return AUTH_FAILED;

	if (!utils_copy_smartcard_settings(settings, origSettings))
		return AUTH_FAILED;

	return AUTH_SUCCESS;
}

static auth_status utils_try_auth(freerdp* instance, rdp_auth_reason reason)
{
	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);

	rdpSettings* settings = instance->context->settings;
	WINPR_ASSERT(settings);

	/* If no callback is specified still continue connection */
	if (!instance->Authenticate && !instance->AuthenticateEx)
		return AUTH_NO_CREDENTIALS;

	auth_status ret = AUTH_CANCELLED;
	const char* CUsername = freerdp_settings_get_string(settings, FreeRDP_Username);
	const char* CDomain = freerdp_settings_get_string(settings, FreeRDP_Domain);
	const char* CPassword = freerdp_settings_get_string(settings, FreeRDP_Password);

	char* Username = nullptr;
	char* Domain = nullptr;
	char* Password = nullptr;
	if (CUsername)
		Username = _strdup(CUsername);
	if (CDomain)
		Domain = _strdup(CDomain);
	if (CPassword)
		Password = _strdup(CPassword);

	if (!instance->Authenticate)
	{
		const BOOL proceed =
		    instance->AuthenticateEx(instance, &Username, &Password, &Domain, reason);
		if (!proceed)
			goto fail;
	}
	else
	{
		const BOOL proceed = instance->Authenticate(instance, &Username, &Password, &Domain);
		if (!proceed)
		{
			ret = AUTH_NO_CREDENTIALS;
			goto fail;
		}
	}

	if (utils_str_is_empty(Username) || utils_str_is_empty(Password))
	{
		ret = AUTH_NO_CREDENTIALS;
		goto fail;
	}

	if (!freerdp_settings_set_string(settings, FreeRDP_Username, Username))
		goto fail;
	if (!freerdp_settings_set_string(settings, FreeRDP_Domain, Domain))
		goto fail;
	if (!freerdp_settings_set_string(settings, FreeRDP_Password, Password))
		goto fail;
	ret = AUTH_SUCCESS;

fail:
	free(Username);
	free(Domain);
	free(Password);
	return ret;
}

auth_status utils_authenticate(freerdp* instance, rdp_auth_reason reason, BOOL override)
{
	rdpSettings* settings = nullptr;
	rdpSettings* origSettings = nullptr;
	BOOL prompt = !override;
	BOOL proceed = 0;

	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);
	WINPR_ASSERT(instance->context->settings);
	WINPR_ASSERT(instance->context->rdp);
	WINPR_ASSERT(instance->context->rdp->originalSettings);

	settings = instance->context->settings;
	origSettings = instance->context->rdp->originalSettings;

	if (freerdp_shall_disconnect_context(instance->context))
		return AUTH_FAILED;

	if (freerdp_settings_get_bool(settings, FreeRDP_ConnectChildSession))
		return AUTH_NO_CREDENTIALS;

	/* Ask for auth data if no or an empty username was specified or no password was given */
	if (utils_settings_str_empty(settings, FreeRDP_Username) ||
	    ((freerdp_settings_get_string(settings, FreeRDP_Password) == nullptr) &&
	     (freerdp_settings_get_pointer(settings, FreeRDP_RedirectionPassword) == nullptr)))
		prompt = TRUE;

	if (!prompt)
		return AUTH_SKIP;

	switch (reason)
	{
		case AUTH_RDP:
		case AUTH_TLS:
			if (freerdp_settings_get_bool(settings, FreeRDP_SmartcardLogon))
			{
				if (!utils_settings_str_empty(settings, FreeRDP_Password))
				{
					WLog_INFO(TAG, "Authentication via smartcard");
					return AUTH_SUCCESS;
				}
				reason = AUTH_SMARTCARD_PIN;
			}
			break;
		case AUTH_NLA:
			if (freerdp_settings_get_bool(settings, FreeRDP_SmartcardLogon))
				reason = AUTH_SMARTCARD_PIN;
			break;
		case AUTH_RDSTLS:
		default:
			break;
	}

	auth_status rc = utils_try_auth(instance, reason);
	switch (rc)
	{
		case AUTH_SKIP:
		case AUTH_SUCCESS:
			break;
		default:
			return rc;
	}

	if (!utils_sync_credentials(settings, TRUE))
		return AUTH_FAILED;

	/* update original settings with provided user credentials */
	if (!utils_settings_str_copy(settings, FreeRDP_Username, FreeRDP_Username))
		return AUTH_FAILED;
	if (!utils_settings_str_copy(settings, FreeRDP_Domain, FreeRDP_Domain))
		return AUTH_FAILED;
	if (!utils_settings_str_copy(settings, FreeRDP_Password, FreeRDP_Password))
		return AUTH_FAILED;
	if (!utils_sync_credentials(origSettings, TRUE))
		return AUTH_FAILED;

	if (!utils_copy_smartcard_settings(settings, origSettings))
		return AUTH_FAILED;

	return AUTH_SUCCESS;
}

BOOL utils_sync_credentials(rdpSettings* settings, BOOL toGateway)
{
	WINPR_ASSERT(settings);
	if (!freerdp_settings_get_bool(settings, FreeRDP_GatewayUseSameCredentials))
		return TRUE;

	if (toGateway)
	{
		if (!utils_settings_str_copy(settings, FreeRDP_Username, FreeRDP_GatewayUsername))
			return FALSE;
		if (!utils_settings_str_copy(settings, FreeRDP_Domain, FreeRDP_GatewayDomain))
			return FALSE;
		if (!utils_settings_str_copy(settings, FreeRDP_Password, FreeRDP_GatewayPassword))
			return FALSE;
	}
	else
	{
		if (!utils_settings_str_copy(settings, FreeRDP_GatewayUsername, FreeRDP_Username))
			return FALSE;
		if (!utils_settings_str_copy(settings, FreeRDP_GatewayDomain, FreeRDP_Domain))
			return FALSE;
		if (!utils_settings_str_copy(settings, FreeRDP_GatewayPassword, FreeRDP_Password))
			return FALSE;
	}
	return TRUE;
}

BOOL utils_persist_credentials(rdpSettings* settings, const rdpSettings* current)
{
	if (!settings || !current)
		return FALSE;

	const SSIZE_T keys[] = { FreeRDP_GatewayUsername, FreeRDP_GatewayDomain,
		                     FreeRDP_GatewayPassword, FreeRDP_Username,
		                     FreeRDP_Domain,          FreeRDP_Password };

	for (size_t x = 0; x < ARRAYSIZE(keys); x++)
	{
		const SSIZE_T key = keys[x];
		if (!freerdp_settings_copy_item(settings, current, key))
		{
			WLog_ERR(TAG, "Failed to copy %s from current to backup settings",
			         freerdp_settings_get_name_for_key(key));
			return FALSE;
		}
	}

	return TRUE;
}

BOOL utils_str_is_empty(const char* str)
{
	if (!str)
		return TRUE;
	if (*str == '\0')
		return TRUE;
	return FALSE;
}

BOOL utils_abort_connect(rdpRdp* rdp)
{
	if (!rdp)
		return FALSE;

	return SetEvent(rdp->abortEvent);
}

BOOL utils_reset_abort(rdpRdp* rdp)
{
	WINPR_ASSERT(rdp);

	return ResetEvent(rdp->abortEvent);
}

HANDLE utils_get_abort_event(rdpRdp* rdp)
{
	WINPR_ASSERT(rdp);
	return rdp->abortEvent;
}

BOOL utils_abort_event_is_set(const rdpRdp* rdp)
{
	DWORD status = 0;
	WINPR_ASSERT(rdp);
	status = WaitForSingleObject(rdp->abortEvent, 0);
	return status == WAIT_OBJECT_0;
}

const char* utils_is_vsock(const char* hostname)
{
	if (!hostname)
		return nullptr;

	const char vsock[8] = { 'v', 's', 'o', 'c', 'k', ':', '/', '/' };
	if (strncmp(hostname, vsock, sizeof(vsock)) == 0)
		return &hostname[sizeof(vsock)];
	return nullptr;
}

static BOOL remove_rdpdr_type(rdpSettings* settings, UINT32 type)
{
	BOOL rc = TRUE;
	RDPDR_DEVICE* printer = nullptr;
	do
	{
		printer = freerdp_device_collection_find_type(settings, type);
		if (printer)
		{
			if (!freerdp_device_collection_del(settings, printer))
				rc = FALSE;
		}
		freerdp_device_free(printer);
	} while (printer);
	return rc;
}

static BOOL disable_clipboard(rdpSettings* settings)
{
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectClipboard, FALSE))
		return FALSE;
	freerdp_static_channel_collection_del(settings, CLIPRDR_SVC_CHANNEL_NAME);
	return TRUE;
}

static BOOL disable_drive(rdpSettings* settings)
{
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectDrives, FALSE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectHomeDrive, FALSE))
		return FALSE;

	return remove_rdpdr_type(settings, RDPDR_DTYP_FILESYSTEM);
}

static BOOL disable_printers(rdpSettings* settings)
{
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectPrinters, FALSE))
		return FALSE;

	return remove_rdpdr_type(settings, RDPDR_DTYP_PRINT);
}

static BOOL disable_port(rdpSettings* settings)
{
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectParallelPorts, FALSE))
		return FALSE;
	if (!freerdp_settings_set_bool(settings, FreeRDP_RedirectSerialPorts, FALSE))
		return FALSE;
	if (!remove_rdpdr_type(settings, RDPDR_DTYP_SERIAL))
		return FALSE;
	return remove_rdpdr_type(settings, RDPDR_DTYP_PARALLEL);
}

static BOOL disable_pnp(WINPR_ATTR_UNUSED rdpSettings* settings)
{
	// TODO(akallabeth): [MS-RDPEPNP] related stuff is disabled.
	return TRUE;
}

static BOOL apply_gw_policy(rdpContext* context)
{
	WINPR_ASSERT(context);
	return utils_reload_channels(context);
}

BOOL utils_apply_gateway_policy(wLog* log, rdpContext* context, UINT32 flags, const char* module)
{
	WINPR_ASSERT(log);
	WINPR_ASSERT(context);

	rdpSettings* settings = context->settings;
	WINPR_ASSERT(settings);

	if (flags & HTTP_TUNNEL_REDIR_ENABLE_ALL)
	{
		WLog_Print(log, WLOG_DEBUG, "[%s] policy allows all redirections", module);
	}
	else if (freerdp_settings_get_bool(settings, FreeRDP_GatewayIgnoreRedirectionPolicy))
	{
		char buffer[128] = WINPR_C_ARRAY_INIT;
		WLog_Print(log, WLOG_INFO, "[%s] policy ignored on user request %s", module,
		           utils_redir_flags_to_string(flags, buffer, sizeof(buffer)));
	}
	else if (flags & HTTP_TUNNEL_REDIR_DISABLE_ALL)
	{
		WLog_Print(log, WLOG_INFO, "[%s] policy denies all redirections", module);
		if (!disable_drive(settings))
			return FALSE;
		if (!disable_printers(settings))
			return FALSE;
		if (!disable_clipboard(settings))
			return FALSE;
		if (!disable_port(settings))
			return FALSE;
		if (!disable_pnp(settings))
			return FALSE;
		if (!apply_gw_policy(context))
			return FALSE;
	}
	else
	{
		if (flags & HTTP_TUNNEL_REDIR_DISABLE_DRIVE)
		{
			WLog_Print(log, WLOG_INFO, "[%s] policy denies drive redirections", module);
			if (!disable_drive(settings))
				return FALSE;
		}
		if (flags & HTTP_TUNNEL_REDIR_DISABLE_PRINTER)
		{
			WLog_Print(log, WLOG_INFO, "[%s] policy denies printer redirections", module);
			if (!disable_printers(settings))
				return FALSE;
		}
		if (flags & HTTP_TUNNEL_REDIR_DISABLE_PORT)
		{
			WLog_Print(log, WLOG_INFO, "[%s] policy denies port redirections", module);
			if (!disable_port(settings))
				return FALSE;
		}
		if (flags & HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD)
		{
			WLog_Print(log, WLOG_INFO, "[%s] policy denies clipboard redirections", module);
			if (!disable_clipboard(settings))
				return FALSE;
		}
		if (flags & HTTP_TUNNEL_REDIR_DISABLE_PNP)
		{
			WLog_Print(log, WLOG_INFO, "[%s] policy denies PNP redirections", module);
			if (!disable_pnp(settings))
				return FALSE;
		}
		if (flags != 0)
		{
			if (!apply_gw_policy(context))
				return FALSE;
		}
	}
	return TRUE;
}

char* utils_redir_flags_to_string(UINT32 flags, char* buffer, size_t size)
{
	winpr_str_append("{", buffer, size, "");
	if (flags & HTTP_TUNNEL_REDIR_ENABLE_ALL)
		winpr_str_append("ENABLE_ALL", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_ALL)
		winpr_str_append("DISABLE_ALL", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_DRIVE)
		winpr_str_append("DISABLE_DRIVE", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_PRINTER)
		winpr_str_append("DISABLE_PRINTER", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_PORT)
		winpr_str_append("DISABLE_PORT", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD)
		winpr_str_append("DISABLE_CLIPBOARD", buffer, size, "|");
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_PNP)
		winpr_str_append("DISABLE_PNP", buffer, size, "|");

	char fbuffer[16] = WINPR_C_ARRAY_INIT;
	(void)_snprintf(fbuffer, sizeof(fbuffer), "[0x%08" PRIx32 "]", flags);

	winpr_str_append(fbuffer, buffer, size, " ");
	winpr_str_append("{", buffer, size, "}");
	return buffer;
}

BOOL utils_reload_channels(rdpContext* context)
{
	WINPR_ASSERT(context);

	if (context->channels)
	{
		freerdp_channels_disconnect(context->channels, context->instance);
		freerdp_channels_close(context->channels, context->instance);
		freerdp_channels_free(context->channels);
	}

	context->channels = freerdp_channels_new(context->instance);
	if (!context->channels)
		return FALSE;

	freerdp_channels_register_instance(context->channels, context->instance);

	BOOL rc = TRUE;
	IFCALLRET(context->instance->LoadChannels, rc, context->instance);
	if (rc)
		return freerdp_channels_pre_connect(context->channels, context->instance) == CHANNEL_RC_OK;
	return rc;
}
