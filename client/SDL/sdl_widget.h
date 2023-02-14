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

#ifndef FREERDP_CLIENT_SDL_WIDGET_H
#define FREERDP_CLIENT_SDL_WIDGET_H

#include <stdbool.h>
#include <SDL.h>
#include <SDL_ttf.h>

typedef struct
{
	SDL_Surface* surface;
	SDL_Texture* texture;
	TTF_Font* font;
	SDL_Rect rect;
	bool input;
} Widget;

typedef struct
{
	char* name;
	int id;
	Widget w;
} ButtonState;

void widget_free(Widget* w);

#define widget_log_error(res, what) widget_log_error_ex(res, what, __FILE__, __LINE__, __FUNCTION__)
bool widget_log_error_ex(Uint32 res, const char* what, const char* file, size_t line,
                         const char* fkt);

bool widget_init(SDL_Renderer* renderer, Widget* w, const SDL_Rect* rect, bool input);

bool widget_fill(SDL_Renderer* renderer, Widget* w, SDL_Color color);

bool widget_update_text(SDL_Renderer* renderer, Widget* w, const char* text, SDL_Color fgcolor,
                        SDL_Color bgcolor);

bool button_init(SDL_Renderer* renderer, ButtonState* button, const char* label, int id,
                 const SDL_Rect* rect);

bool button_highlight(SDL_Renderer* renderer, ButtonState* button);
ButtonState* button_get_selected(ButtonState* buttons, size_t count,
                                 const SDL_MouseButtonEvent* button);
bool button_update(SDL_Renderer* renderer, ButtonState* button);

void buttons_free(ButtonState* buttons, size_t count);
bool buttons_init(SDL_Renderer* renderer, size_t count, ButtonState* buttons, const char** labels,
                  const int* ids, Sint32 offsetY, Sint32 width, Sint32 heigth);
bool buttons_update(SDL_Renderer* renderer, ButtonState* buttons, size_t count);

bool clear_window(SDL_Renderer* renderer);

#endif /* FREERDP_CLIENT_SDL_WIDGET_H */
