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

#ifndef FREERDP_CLIENT_SDL_INPUT_H
#define FREERDP_CLIENT_SDL_INPUT_H

#include <SDL.h>

enum
{
	SDL_INPUT_MASK = 1
};

int sdl_input_get(const char* title, Uint32 count, const char* labels[], const char* initial[],
                  const Uint32 flags[], char* result[]);

#endif /* FREERDP_CLIENT_SDL_INPUT_H */
