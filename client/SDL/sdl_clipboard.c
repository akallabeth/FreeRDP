/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * SDL Client clipboard
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

#include <winpr/clipboard.h>
#include <freerdp/client/client_cliprdr_file.h>

#include "sdl_freerdp.h"
#include "sdl_clipboard.h"

#include <freerdp/log.h>

#define TAG CLIENT_TAG("sdl.cliprdr")

#define mime_text_plain "text/plain"
#define mime_text_utf8 mime_text_plain ";charset=utf-8"

struct sdl_clipboard
{
	sdlContext* sdl;
	rdpChannels* channels;
	CliprdrClientContext* context;
	wLog* log;

	wClipboard* system;

	size_t numClientFormats;
	CLIPRDR_FORMAT* clientFormats;

	size_t numServerFormats;
	CLIPRDR_FORMAT* serverFormats;

	BOOL sync;

	CRITICAL_SECTION lock;
	CliprdrFileContext* file;

	wQueue* request_queue;
};

typedef struct
{
	FILE* responseFile;
	UINT32 responseFormat;
	char* responseMime;
} sdl_request;

static const char* mime_text[] = { mime_text_plain, mime_text_utf8, "UTF8_STRING",
								   "COMPOUND_TEXT", "TEXT",         "STRING" };

static const char* mime_image[] = {
	"image/png",       "image/bmp",   "image/x-bmp",        "image/x-MS-bmp",
	"image/x-icon",    "image/x-ico", "image/x-win-bitmap", "image/vmd.microsoft.icon",
	"application/ico", "image/ico",   "image/icon",         "image/jpeg",
	"image/gif",       "image/tiff"
};

static const char mime_uri_list[] = "text/uri-list";
static const char mime_html[] = "text/html";
static const char mime_bmp[] = "image/bmp";

static const char mime_gnome_copied_files[] = "x-special/gnome-copied-files";
static const char mime_mate_copied_files[] = "x-special/mate-copied-files";

static const char type_FileGroupDescriptorW[] = "FileGroupDescriptorW";
static const char type_HtmlFormat[] = "HTML Format";

static void sdl_request_free(void* rq)
{
	sdl_request* request = rq;
	if (request)
	{
		free(request->responseMime);
		if (request->responseFile)
			fclose(request->responseFile);
	}
	free(request);
}

static sdl_request* wlf_request_new(void)
{
	return calloc(1, sizeof(sdl_request));
}

static void* sdl_request_clone(const void* oth)
{
	const sdl_request* other = (const sdl_request*)oth;
	sdl_request* copy = wlf_request_new();
	if (!copy)
		return NULL;
	*copy = *other;
	if (other->responseMime)
	{
		copy->responseMime = _strdup(other->responseMime);
		if (!copy->responseMime)
			goto fail;
	}
	return copy;
fail:
	sdl_request_free(copy);
	return NULL;
}

sdlClipboard* sdl_clipboard_new(sdlContext* sdl)
{
	rdpChannels* channels;
	sdlClipboard* clipboard;

	WINPR_ASSERT(sdl);

	clipboard = (sdlClipboard*)calloc(1, sizeof(sdlClipboard));

	if (!clipboard)
		goto fail;

	InitializeCriticalSection(&clipboard->lock);
	clipboard->sdl = sdl;
	channels = sdl->common.context.channels;
	clipboard->log = WLog_Get(TAG);
	clipboard->channels = channels;
	clipboard->system = ClipboardCreate();
	if (!clipboard->system)
		goto fail;

	clipboard->file = cliprdr_file_context_new(clipboard);
	if (!clipboard->file)
		goto fail;

	if (!cliprdr_file_context_set_locally_available(clipboard->file, TRUE))
		goto fail;

	clipboard->request_queue = Queue_New(TRUE, -1, -1);
	if (!clipboard->request_queue)
		goto fail;

	wObject* obj = Queue_Object(clipboard->request_queue);
	WINPR_ASSERT(obj);
	obj->fnObjectFree = sdl_request_free;
	obj->fnObjectNew = sdl_request_clone;

	return clipboard;

fail:
	sdl_clipboard_free(clipboard);
	return NULL;
}

void sdl_clipboard_free(sdlClipboard* clipboard)
{
	if (!clipboard)
		return;

	cliprdr_file_context_free(clipboard->file);

	// wlf_cliprdr_free_server_formats(clipboard);
	// wlf_cliprdr_free_client_formats(clipboard);
	ClipboardDestroy(clipboard->system);

	EnterCriticalSection(&clipboard->lock);

	Queue_Free(clipboard->request_queue);
	LeaveCriticalSection(&clipboard->lock);
	DeleteCriticalSection(&clipboard->lock);
	free(clipboard);
}

static UINT sdl_cliprdr_monitor_ready(CliprdrClientContext* context,
									  const CLIPRDR_MONITOR_READY* monitorReady)
{
	UINT ret;

	WINPR_UNUSED(monitorReady);
	WINPR_ASSERT(context);
	WINPR_ASSERT(monitorReady);

	sdlClipboard* clipboard = cliprdr_file_context_get_context(context->custom);
	WINPR_ASSERT(clipboard);

	if ((ret = sdl_cliprdr_send_client_capabilities(clipboard)) != CHANNEL_RC_OK)
		return ret;

	if ((ret = sdl_cliprdr_send_client_format_list(clipboard)) != CHANNEL_RC_OK)
		return ret;

	clipboard->sync = TRUE;
	return CHANNEL_RC_OK;
}

static UINT sdl_cliprdr_server_capabilities(CliprdrClientContext* context,
											const CLIPRDR_CAPABILITIES* capabilities)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(capabilities);

	const BYTE* capsPtr = (const BYTE*)capabilities->capabilitySets;
	WINPR_ASSERT(capsPtr);

	sdlClipboard* clipboard = cliprdr_file_context_get_context(context->custom);
	WINPR_ASSERT(clipboard);

	if (!cliprdr_file_context_remote_set_flags(clipboard->file, 0))
		return ERROR_INTERNAL_ERROR;

	for (UINT32 i = 0; i < capabilities->cCapabilitiesSets; i++)
	{
		const CLIPRDR_CAPABILITY_SET* caps = (const CLIPRDR_CAPABILITY_SET*)capsPtr;

		if (caps->capabilitySetType == CB_CAPSTYPE_GENERAL)
		{
			const CLIPRDR_GENERAL_CAPABILITY_SET* generalCaps =
				(const CLIPRDR_GENERAL_CAPABILITY_SET*)caps;

			if (!cliprdr_file_context_remote_set_flags(clipboard->file, generalCaps->generalFlags))
				return ERROR_INTERNAL_ERROR;
		}

		capsPtr += caps->capabilitySetLength;
	}

	return CHANNEL_RC_OK;
}

static UINT sdl_cliprdr_server_format_list(CliprdrClientContext* context,
										  const CLIPRDR_FORMAT_LIST* formatList)
{
	sdlContext* sdl;
	UINT ret;
	sdlClipboard* clipboard;

	WINPR_ASSERT(context);
	WINPR_ASSERT(formatList);

	clipboard = cliprdr_file_context_get_context(context->custom);
	WINPR_ASSERT(clipboard);

	sdl = clipboard->sdl;
	WINPR_ASSERT(sdl);

	sdl_clipboard_formats_free(clipboard);
	sdl_cliprdr_clear_cached_data(clipboard);

	sdl_clipboard_free_server_formats(clipboard);

	clipboard->numServerFormats = formatList->numFormats + 1; /* +1 for CF_RAW */

	if (!(clipboard->serverFormats =
		  (CLIPRDR_FORMAT*)calloc(clipboard->numServerFormats, sizeof(CLIPRDR_FORMAT))))
	{
		WLog_ERR(TAG, "failed to allocate %d CLIPRDR_FORMAT structs", clipboard->numServerFormats);
		return CHANNEL_RC_NO_MEMORY;
	}

	for (size_t i = 0; i < formatList->numFormats; i++)
	{
		const CLIPRDR_FORMAT* format = &formatList->formats[i];
		CLIPRDR_FORMAT* srvFormat = &clipboard->serverFormats[i];

		srvFormat->formatId = format->formatId;

		if (format->formatName)
		{
			srvFormat->formatName = _strdup(format->formatName);

			if (!srvFormat->formatName)
			{
				UINT32 k;

				for (k = 0; k < i; k++)
					free(clipboard->serverFormats[k].formatName);

				clipboard->numServerFormats = 0;
				free(clipboard->serverFormats);
				clipboard->serverFormats = NULL;
				return CHANNEL_RC_NO_MEMORY;
			}
		}
	}

	/* CF_RAW is always implicitly supported by the server */
	{
		CLIPRDR_FORMAT* format = &clipboard->serverFormats[formatList->numFormats];
		format->formatId = CF_RAW;
		format->formatName = NULL;
	}
	sdl_cliprdr_provide_server_format_list(clipboard);
	clipboard->numTargets = 2;

	for (size_t i = 0; i < formatList->numFormats; i++)
	{
		const CLIPRDR_FORMAT* format = &formatList->formats[i];

		for (size_t j = 0; j < clipboard->numClientFormats; j++)
		{
			const xfCliprdrFormat* clientFormat = &clipboard->clientFormats[j];
			if (xf_cliprdr_formats_equal(format, clientFormat))
			{
				if ((clientFormat->formatName != NULL) &&
					(strcmp(type_FileGroupDescriptorW, clientFormat->formatName) == 0))
				{
					if (!cliprdr_file_context_has_local_support(clipboard->file))
						continue;
				}
				xf_cliprdr_append_target(clipboard, clientFormat->atom);
			}
		}
	}

	ret = sdl_cliprdr_send_client_format_list_response(clipboard, TRUE);
	if (xfc->remote_app)
		sdl_cliprdr_set_selection_owner(xfc, clipboard, CurrentTime);
	else
		sdl_cliprdr_prepare_to_set_selection_owner(xfc, clipboard);
	return ret;
}

static UINT
sdl_cliprdr_server_format_list_response(CliprdrClientContext* context,
									   const CLIPRDR_FORMAT_LIST_RESPONSE* formatListResponse)
{
	WINPR_ASSERT(context);
	WINPR_ASSERT(formatListResponse);
	// xfClipboard* clipboard = (xfClipboard*) context->custom;
	return CHANNEL_RC_OK;
}

static UINT
sdl_cliprdr_server_format_data_request(CliprdrClientContext* context,
									   const CLIPRDR_FORMAT_DATA_REQUEST* formatDataRequest)
{
	UINT rc = CHANNEL_RC_OK;
	BYTE* data = NULL;
	size_t size = 0;
	const char* mime = NULL;
	UINT32 formatId = 0;
	UINT32 localFormatId = 0;
	sdlClipboard* clipboard = 0;

	UINT32 dsize = 0;
	BYTE* ddata = NULL;

	WINPR_ASSERT(context);
	WINPR_ASSERT(formatDataRequest);

	localFormatId = formatId = formatDataRequest->requestedFormatId;
	clipboard = cliprdr_file_context_get_context(context->custom);
	WINPR_ASSERT(clipboard);

	ClipboardLock(clipboard->system);
	const UINT32 fileFormatId = ClipboardGetFormatId(clipboard->system, type_FileGroupDescriptorW);
	const UINT32 htmlFormatId = ClipboardGetFormatId(clipboard->system, type_HtmlFormat);

	switch (formatId)
	{
		case CF_TEXT:
		case CF_OEMTEXT:
		case CF_UNICODETEXT:
			localFormatId = ClipboardGetFormatId(clipboard->system, mime_text_plain);
			mime = mime_text_utf8;
			break;

		case CF_DIB:
		case CF_DIBV5:
			mime = mime_bmp;
			break;

		default:
			if (formatId == fileFormatId)
			{
				localFormatId = ClipboardGetFormatId(clipboard->system, mime_uri_list);
				mime = mime_uri_list;
			}
			else if (formatId == htmlFormatId)
			{
				localFormatId = ClipboardGetFormatId(clipboard->system, mime_html);
				mime = mime_html;
			}
			else
				goto fail;
			break;
	}

	data = UwacClipboardDataGet(clipboard->seat, mime, &size);

	if (!data)
		goto fail;

	if (fileFormatId == formatId)
	{
		if (!cliprdr_file_context_update_client_data(clipboard->file, data, size))
			goto fail;
	}

	const BOOL res = ClipboardSetData(clipboard->system, localFormatId, data, size);
	free(data);

	UINT32 len = 0;
	data = NULL;
	if (res)
		data = ClipboardGetData(clipboard->system, formatId, &len);

	if (!res || !data)
		goto fail;

	if (fileFormatId == formatId)
	{
		const UINT32 flags = cliprdr_file_context_remote_get_flags(clipboard->file);
		const UINT32 error = cliprdr_serialize_file_list_ex(
			flags, (const FILEDESCRIPTORW*)data, len / sizeof(FILEDESCRIPTORW), &ddata, &dsize);
		if (error)
			goto fail;
	}
fail:
	ClipboardUnlock(clipboard->system);
	rc = sdl_cliprdr_send_data_response(clipboard, ddata, dsize);
	free(data);
	return rc;
}

static UINT
sdl_cliprdr_server_format_data_response(CliprdrClientContext* context,
										const CLIPRDR_FORMAT_DATA_RESPONSE* formatDataResponse)
{
	UINT rc = ERROR_INTERNAL_ERROR;

	WINPR_ASSERT(context);
	WINPR_ASSERT(formatDataResponse);

	const UINT32 size = formatDataResponse->common.dataLen;
	const BYTE* data = formatDataResponse->requestedFormatData;

	sdlClipboard* clipboard = cliprdr_file_context_get_context(context->custom);
	WINPR_ASSERT(clipboard);

	sdl_request* request = Queue_Dequeue(clipboard->request_queue);
	if (!request)
		goto fail;

	rc = CHANNEL_RC_OK;
	if (formatDataResponse->common.msgFlags & CB_RESPONSE_FAIL)
	{
		WLog_WARN(TAG, "clipboard data request for format %" PRIu32 " [%s], mime %s failed",
				  request->responseFormat, ClipboardGetFormatIdString(request->responseFormat),
				  request->responseMime);
		goto fail;
	}
	rc = ERROR_INTERNAL_ERROR;

	ClipboardLock(clipboard->system);
	EnterCriticalSection(&clipboard->lock);

	UINT32 srcFormatId = 0;
	UINT32 dstFormatId = 0;
	switch (request->responseFormat)
	{
		case CF_TEXT:
		case CF_OEMTEXT:
		case CF_UNICODETEXT:
			srcFormatId = request->responseFormat;
			dstFormatId = ClipboardGetFormatId(clipboard->system, request->responseMime);
			break;

		case CF_DIB:
		case CF_DIBV5:
			srcFormatId = request->responseFormat;
			dstFormatId = ClipboardGetFormatId(clipboard->system, request->responseMime);
			break;

		default:
		{
			const char* name = sdl_get_server_format_name(clipboard, request->responseFormat);
			if (name)
			{
				if (strcmp(type_FileGroupDescriptorW, name) == 0)
				{
					srcFormatId =
						ClipboardGetFormatId(clipboard->system, type_FileGroupDescriptorW);
					dstFormatId = ClipboardGetFormatId(clipboard->system, request->responseMime);

					if (!cliprdr_file_context_update_server_data(clipboard->file, clipboard->system,
																 data, size))
						goto unlock;
				}
				else if (strcmp(type_HtmlFormat, name) == 0)
				{
					srcFormatId = ClipboardGetFormatId(clipboard->system, type_HtmlFormat);
					dstFormatId = ClipboardGetFormatId(clipboard->system, request->responseMime);
				}
			}
		}
		break;
	}

	UINT32 len = 0;

	const BOOL sres = ClipboardSetData(clipboard->system, srcFormatId, data, size);
	if (sres)
		data = ClipboardGetData(clipboard->system, dstFormatId, &len);

	if (!sres || !data)
		goto unlock;

	if (request->responseFile)
	{
		const size_t res = fwrite(data, 1, len, request->responseFile);
		if (res == len)
			rc = CHANNEL_RC_OK;
	}
	else
		rc = CHANNEL_RC_OK;

unlock:
	ClipboardUnlock(clipboard->system);
	LeaveCriticalSection(&clipboard->lock);
fail:
	sdl_request_free(request);
	return rc;
}

BOOL sdl_cliprdr_init(sdlClipboard* clipboard, CliprdrClientContext* cliprdr)
{
	WINPR_ASSERT(clipboard);
	WINPR_ASSERT(cliprdr);

	cliprdr->custom = clipboard->sdl;
	clipboard->context = cliprdr;

	cliprdr->MonitorReady = sdl_cliprdr_monitor_ready;
	cliprdr->ServerCapabilities = sdl_cliprdr_server_capabilities;
	cliprdr->ServerFormatList = sdl_cliprdr_server_format_list;
	cliprdr->ServerFormatListResponse = sdl_cliprdr_server_format_list_response;
	cliprdr->ServerFormatDataRequest =  sdl_cliprdr_server_format_data_request;
	cliprdr->ServerFormatDataResponse = sdl_cliprdr_server_format_data_response;

	cliprdr_file_context_init(clipboard->file, cliprdr);
}

BOOL sdl_cliprdr_uninit(sdlClipboard* clipboard, CliprdrClientContext* cliprdr)
{
	WINPR_ASSERT(clipboard);
	if (!cliprdr_file_context_uninit(clipboard->file, cliprdr))
		return FALSE;

	if (cliprdr)
		cliprdr->custom = NULL;

	return TRUE;
}

BOOL sdl_cliprdr_handle_event(sdlClipboard* clipboard)
{
	return TRUE;
}
