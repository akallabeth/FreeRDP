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

#ifndef FREERDP_CLIENT_SDL_CLIP_H
#define FREERDP_CLIENT_SDL_CLIP_H

#include <freerdp/client/cliprdr.h>

#include "sdl_types.h"

typedef struct sdl_clipboard sdlClipboard;

sdlClipboard* sdl_clipboard_new(sdlContext* wlc);
void sdl_clipboard_free(sdlClipboard* clipboard);

BOOL sdl_cliprdr_init(sdlClipboard* clipboard, CliprdrClientContext* cliprdr);
BOOL sdl_cliprdr_uninit(sdlClipboard* clipboard, CliprdrClientContext* cliprdr);

BOOL sdl_cliprdr_handle_event(sdlClipboard* clipboard);

#endif /* FREERDP_CLIENT_SDL_CLIP_H */
