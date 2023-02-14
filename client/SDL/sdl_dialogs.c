/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * SDL Client helper dialogs
 *
 * Copyright 2023 Armin Novak <armin.novak@thincast.com>
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

#include <freerdp/log.h>
#include <freerdp/utils/smartcardlogon.h>

#include <SDL.h>

#include "sdl_dialogs.h"
#include "sdl_utils.h"
#include "sdl_input.h"
#include "sdl_select.h"

#define TAG CLIENT_TAG("SDL.dialogs")

enum
{
	SHOW_DIALOG_ACCEPT_REJECT = 1,
	SHOW_DIALOG_TIMED_ACCEPT = 2
};

static int allocating_sprintf(char** dst, const char* fmt, ...)
{
	int rc;
	va_list ap;

	WINPR_ASSERT(dst);

	va_start(ap, fmt);
	rc = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (rc < 0)
		return rc;

	{
		char* tmp = realloc(*dst, (size_t)rc + 1);
		if (!tmp)
			return -1;
		*dst = tmp;
	}
	va_start(ap, fmt);
	rc = vsnprintf(*dst, (size_t)rc + 1, fmt, ap);
	va_end(ap);
	return rc;
}

static const char* type_str_for_flags(UINT32 flags)
{
	const char* type = "RDP-Server";

	if (flags & VERIFY_CERT_FLAG_GATEWAY)
		type = "RDP-Gateway";

	if (flags & VERIFY_CERT_FLAG_REDIRECT)
		type = "RDP-Redirect";
	return type;
}

static int sdl_show_dialog(rdpContext* context, const char* title, const char* message,
                           Sint32 flags)
{
	if (!sdl_push_user_event(SDL_USEREVENT_SHOW_DIALOG, title, message, flags))
		return 0;

	while (!freerdp_shall_disconnect_context(context))
	{
		SDL_Event event = { 0 };
		const int rc = SDL_PeepEvents(&event, 1, SDL_GETEVENT, SDL_USEREVENT_SHOW_RESULT,
		                              SDL_USEREVENT_SHOW_RESULT);
		if (rc > 0)
			return event.user.code;
		Sleep(1);
	}
	return 0;
}

BOOL sdl_authenticate_ex(freerdp* instance, char** username, char** password, char** domain,
                         rdp_auth_reason reason)
{
	BOOL res = FALSE;

	const char* target = freerdp_settings_get_server_name(instance->context->settings);
	switch (reason)
	{
		case GW_AUTH_HTTP:
		case GW_AUTH_RDG:
		case GW_AUTH_RPC:
			target =
			    freerdp_settings_get_string(instance->context->settings, FreeRDP_GatewayHostname);
			break;
		default:
			break;
	}

	char* title = NULL;
	allocating_sprintf(&title, "Credentials required for %s", target);

	char* u = NULL;
	char* d = NULL;
	char* p = NULL;

	if (username)
		u = *username;
	if (domain)
		d = *domain;
	if (password)
		p = *password;
	if (!sdl_push_user_event(SDL_USEREVENT_AUTH_DIALOG, title, u, d, p, reason))
		goto fail;

	while (!freerdp_shall_disconnect_context(instance->context))
	{
		SDL_Event event = { 0 };
		const int rc = SDL_PeepEvents(&event, 1, SDL_GETEVENT, SDL_USEREVENT_AUTH_RESULT,
		                              SDL_USEREVENT_AUTH_RESULT);
		if (rc > 0)
		{
			SDL_UserAuthArg* arg = (SDL_UserAuthArg*)event.padding;

			res = arg->result != 0 ? TRUE : FALSE;

			free(*username);
			free(*domain);
			free(*password);
			*username = arg->user;
			*domain = arg->domain;
			*password = arg->password;
			break;
		}
		Sleep(1);
	}
fail:
	free(title);
	return res;
}

BOOL sdl_choose_smartcard(freerdp* instance, SmartcardCertInfo** cert_list, DWORD count,
                          DWORD* choice, BOOL gateway)
{
	BOOL res = FALSE;
	char** list = calloc(count, sizeof(char*));
	if (!list)
		return FALSE;

	for (DWORD i = 0; i < count; i++)
	{
		const SmartcardCertInfo* cert = cert_list[i];
		char* reader = ConvertWCharToUtf8Alloc(cert->reader, NULL);
		char* container_name = ConvertWCharToUtf8Alloc(cert->containerName, NULL);

		allocating_sprintf(
		    &list[i], "%s\n\tReader: %s\n\tUser: %s@%s\n\tSubject: %s\n\tIssuer: %s\n\tUPN: %s",
		    container_name, reader, cert->userHint, cert->domainHint, cert->subject, cert->issuer,
		    cert->upn);

		free(reader);
		free(container_name);
	}

	const char* title = "Select a logon smartcard certificate";
	if (gateway)
		title = "Select a gateway logon smartcard certificate";
	if (!sdl_push_user_event(SDL_USEREVENT_SCARD_DIALOG, title, list, count))
		goto fail;

	while (!freerdp_shall_disconnect_context(instance->context))
	{
		SDL_Event event = { 0 };
		const int rc = SDL_PeepEvents(&event, 1, SDL_GETEVENT, SDL_USEREVENT_SCARD_RESULT,
		                              SDL_USEREVENT_SCARD_RESULT);
		if (rc > 0)
		{
			res = TRUE;
			*choice = (DWORD)event.user.code;
			break;
		}
		Sleep(1);
	}

fail:
	if (list)
	{
		for (DWORD i = 0; i < count; i++)
			free(list[i]);
	}
	free(list);
	return res;
}

BOOL sdl_present_gateway_message(freerdp* instance, UINT32 type, BOOL isDisplayMandatory,
                                 BOOL isConsentMandatory, size_t length, const WCHAR* wmessage)
{
	if (!isDisplayMandatory)
		return TRUE;

	char* title = NULL;
	allocating_sprintf(&title, "[gateway]");

	Sint32 flags = 0;
	if (isConsentMandatory)
		flags = SHOW_DIALOG_ACCEPT_REJECT;
	else if (isDisplayMandatory)
		flags = SHOW_DIALOG_TIMED_ACCEPT;
	char* message = ConvertWCharNToUtf8Alloc(wmessage, length, NULL);

	const int rc = sdl_show_dialog(instance->context, title, message, flags);
	free(title);
	free(message);
	return rc > 0 ? TRUE : FALSE;
}

int sdl_logon_error_info(freerdp* instance, UINT32 data, UINT32 type)
{
	int rc = -1;
	sdlContext* tf;
	const char* str_data = freerdp_get_logon_error_info_data(data);
	const char* str_type = freerdp_get_logon_error_info_type(type);

	if (!instance || !instance->context)
		return -1;

	tf = (sdlContext*)instance->context;

	char* title = NULL;
	allocating_sprintf(&title, "[%s] info",
	                   freerdp_settings_get_server_name(tf->common.context.settings));

	char* message = NULL;
	allocating_sprintf(&message, "Logon Error Info %s [%s]", str_data, str_type);

	rc = sdl_show_dialog(instance->context, title, message, SHOW_DIALOG_ACCEPT_REJECT);
	free(title);
	free(message);
	return rc;
}

static DWORD sdl_show_ceritifcate_dialog(rdpContext* context, const char* title,
                                         const char* message)
{
	if (!sdl_push_user_event(SDL_USEREVENT_CERT_DIALOG, title, message))
		return 0;

	while (!freerdp_shall_disconnect_context(context))
	{
		SDL_Event event = { 0 };
		const int rc = SDL_PeepEvents(&event, 1, SDL_GETEVENT, SDL_USEREVENT_CERT_RESULT,
		                              SDL_USEREVENT_CERT_RESULT);
		if (rc > 0)
			return (DWORD)event.user.code;
		Sleep(1);
	}
	return 0;
}

DWORD sdl_verify_changed_certificate_ex(freerdp* instance, const char* host, UINT16 port,
                                        const char* common_name, const char* subject,
                                        const char* issuer, const char* new_fingerprint,
                                        const char* old_subject, const char* old_issuer,
                                        const char* old_fingerprint, DWORD flags)
{
	const char* type = type_str_for_flags(flags);

	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);
	WINPR_ASSERT(instance->context->settings);

	/* Newer versions of FreeRDP allow exposing the whole PEM by setting
	 * FreeRDP_CertificateCallbackPreferPEM to TRUE
	 */
	char* new_fp_str = NULL;
	if (flags & VERIFY_CERT_FLAG_FP_IS_PEM)
	{
		allocating_sprintf(&new_fp_str,
		                   "----------- Certificate --------------\n"
		                   "%s\n"
		                   "--------------------------------------\n",
		                   new_fingerprint);
	}
	else
		allocating_sprintf(&new_fp_str, "Thumbprint:  %s\n", new_fingerprint);

	/* Newer versions of FreeRDP allow exposing the whole PEM by setting
	 * FreeRDP_CertificateCallbackPreferPEM to TRUE
	 */
	char* old_fp_str = NULL;
	if (flags & VERIFY_CERT_FLAG_FP_IS_PEM)
	{
		allocating_sprintf(&old_fp_str,
		                   "----------- Certificate --------------\n"
		                   "%s\n"
		                   "--------------------------------------\n",
		                   old_fingerprint);
	}
	else
		allocating_sprintf(&old_fp_str, "Thumbprint:  %s\n", old_fingerprint);

	const char* collission_str = "";
	if (flags & VERIFY_CERT_FLAG_MATCH_LEGACY_SHA1)
	{
		collission_str =
		    "A matching entry with legacy SHA1 was found in local known_hosts2 store.\n"
		    "If you just upgraded from a FreeRDP version before 2.0 this is expected.\n"
		    "The hashing algorithm has been upgraded from SHA1 to SHA256.\n"
		    "All manually accepted certificates must be reconfirmed!\n"
		    "\n";
	}

	char* title = NULL;
	allocating_sprintf(&title, "Certificate for %s:%" PRIu16 " (%s) has changed", host, port, type);

	char* message = NULL;
	allocating_sprintf(
	    &message,
	    "New Certificate details:\n"
	    "Common Name: %s\n"
	    "Subject:     %s\n"
	    "Issuer:      %s\n"
	    "%s\n"
	    "Old Certificate details:\n"
	    "Subject:     %s\n"
	    "Issuer:      %s\n"
	    "%s\n"
	    "%s\n"
	    "The above X.509 certificate does not match the certificate used for previous "
	    "connections.\n"
	    "This may indicate that the certificate has been tampered with.\n"
	    "Please contact the administrator of the RDP server and clarify.\n",
	    common_name, subject, issuer, new_fp_str, old_subject, old_issuer, old_fp_str,
	    collission_str);

	const DWORD rc = sdl_show_ceritifcate_dialog(instance->context, title, message);
	free(title);
	free(message);
	free(new_fp_str);
	free(old_fp_str);

	return rc;
}

DWORD sdl_verify_certificate_ex(freerdp* instance, const char* host, UINT16 port,
                                const char* common_name, const char* subject, const char* issuer,
                                const char* fingerprint, DWORD flags)
{
	const char* type = type_str_for_flags(flags);

	/* Newer versions of FreeRDP allow exposing the whole PEM by setting
	 * FreeRDP_CertificateCallbackPreferPEM to TRUE
	 */
	char* fp_str = NULL;
	if (flags & VERIFY_CERT_FLAG_FP_IS_PEM)
	{
		allocating_sprintf(&fp_str,
		                   "----------- Certificate --------------\n"
		                   "%s\n"
		                   "--------------------------------------\n",
		                   fingerprint);
	}
	else
		allocating_sprintf(&fp_str, "Thumbprint:  %s\n", fingerprint);

	char* title = NULL;
	allocating_sprintf(&title, "New certificate for %s:%" PRIu16 " (%s)", host, port, type);

	char* message = NULL;
	allocating_sprintf(
	    &message,
	    "Common Name: %s\n"
	    "Subject:     %s\n"
	    "Issuer:      %s\n"
	    "%s\n"
	    "The above X.509 certificate could not be verified, possibly because you do not have\n"
	    "the CA certificate in your certificate store, or the certificate has expired.\n"
	    "Please look at the OpenSSL documentation on how to add a private CA to the store.\n",
	    common_name, subject, issuer, fp_str);

	const DWORD rc = sdl_show_ceritifcate_dialog(instance->context, title, message);
	free(fp_str);
	free(title);
	free(message);
	return rc;
}

BOOL sdl_cert_dialog_show(const char* title, const char* message)
{
	int buttonid = -1;
	enum
	{
		BUTTONID_CERT_ACCEPT_PERMANENT = 23,
		BUTTONID_CERT_ACCEPT_TEMPORARY = 24,
		BUTTONID_CERT_DENY = 25
	};
	const SDL_MessageBoxButtonData buttons[] = {
		{ .flags = 0, .buttonid = BUTTONID_CERT_ACCEPT_PERMANENT, .text = "permanent" },
		{ .flags = SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT,
		  .buttonid = BUTTONID_CERT_ACCEPT_TEMPORARY,
		  .text = "temporary" },
		{ .flags = SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT,
		  .buttonid = BUTTONID_CERT_DENY,
		  .text = "cancel" }
	};

	const SDL_MessageBoxData data = { .flags = SDL_MESSAGEBOX_WARNING,
		                              .window = NULL,
		                              .title = title,
		                              .message = message,
		                              .numbuttons = ARRAYSIZE(buttons),
		                              .buttons = buttons,
		                              .colorScheme = NULL };
	const int rc = SDL_ShowMessageBox(&data, &buttonid);

	Sint32 value = -1;
	if (rc < 0)
		value = 0;
	else
	{
		switch (buttonid)
		{
			case BUTTONID_CERT_ACCEPT_PERMANENT:
				value = 1;
				break;
			case BUTTONID_CERT_ACCEPT_TEMPORARY:
				value = 2;
				break;
			default:
				value = 0;
				break;
		}
	}

	return sdl_push_user_event(SDL_USEREVENT_CERT_RESULT, value);
}

BOOL sdl_message_dialog_show(const char* title, const char* message, Sint32 flags)
{
	int buttonid = -1;
	enum
	{
		BUTTONID_SHOW_ACCEPT = 24,
		BUTTONID_SHOW_DENY = 25
	};
	const SDL_MessageBoxButtonData buttons[] = { { .flags = SDL_MESSAGEBOX_BUTTON_RETURNKEY_DEFAULT,
		                                           .buttonid = BUTTONID_SHOW_ACCEPT,
		                                           .text = "accept" },
		                                         { .flags = SDL_MESSAGEBOX_BUTTON_ESCAPEKEY_DEFAULT,
		                                           .buttonid = BUTTONID_SHOW_DENY,
		                                           .text = "cancel" } };

	const int button_cnt = (flags & SHOW_DIALOG_ACCEPT_REJECT) ? 2 : 1;
	const SDL_MessageBoxData data = { .flags = SDL_MESSAGEBOX_WARNING,
		                              .window = NULL,
		                              .title = title,
		                              .message = message,
		                              .numbuttons = button_cnt,
		                              .buttons = buttons,
		                              .colorScheme = NULL };
	const int rc = SDL_ShowMessageBox(&data, &buttonid);

	Sint32 value = -1;
	if (rc < 0)
		value = 0;
	else
	{
		switch (buttonid)
		{
			case BUTTONID_SHOW_ACCEPT:
				value = 1;
				break;
			default:
				value = 0;
				break;
		}
	}

	return sdl_push_user_event(SDL_USEREVENT_SHOW_RESULT, value);
}

BOOL sdl_auth_dialog_show(const SDL_UserAuthArg* args)
{
	const char* auth[] = { "Username:        ", "Domain:          ", "Password:        " };
	const char* authPin[] = { "Username:        ", "Domain:          ", "Smartcard-Pin:   " };
	const char* gw[] = { "GatewayUsername: ", "GatewayDomain:   ", "GatewayPassword: " };
	const char** prompt = NULL;
	BOOL pinOnly = FALSE;
	Sint32 rc = -1;

	switch (args->result)
	{
		case AUTH_SMARTCARD_PIN:
			prompt = authPin;
			pinOnly = TRUE;
			break;
		case AUTH_TLS:
		case AUTH_RDP:
		case AUTH_NLA:
			prompt = auth;
			break;
		case GW_AUTH_HTTP:
		case GW_AUTH_RDG:
		case GW_AUTH_RPC:
			prompt = gw;
			break;
		default:
			break;
	}

	const char* result[] = { NULL, NULL, NULL };
	if (prompt)
	{
		const char* initial[] = { args->user, args->domain, args->password };
		const Uint32 flags[] = { 0, 0, SDL_INPUT_MASK };
		rc = sdl_input_get(args->title, 3, prompt, initial, flags, result);
	}

	if (rc <= 0)
	{
		for (size_t x = 0; x < ARRAYSIZE(result); x++)
		{
			free(result[x]);
			result[x] = NULL;
		}
	}

	return sdl_push_user_event(SDL_USEREVENT_AUTH_RESULT, result[0], result[1], result[2], rc);
}

BOOL sdl_scard_dialog_show(const char* title, Sint32 count, const char** list)
{
	Sint32 value = sdl_select_get(title, count, list);
	return sdl_push_user_event(SDL_USEREVENT_SCARD_RESULT, value);
}
