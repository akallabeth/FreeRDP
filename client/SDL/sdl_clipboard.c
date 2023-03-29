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
	// obj->fnObjectFree = wlf_request_free;
	// obj->fnObjectNew = wlf_request_clone;

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

BOOL sdl_cliprdr_init(sdlClipboard* clipboard, CliprdrClientContext* cliprdr)
{
	return TRUE;
}

BOOL sdl_cliprdr_uninit(sdlClipboard* clipboard, CliprdrClientContext* cliprdr)
{
	return TRUE;
}

BOOL sdl_cliprdr_handle_event(sdlClipboard* clipboard)
{
	return TRUE;
}
