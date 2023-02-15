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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <SDL.h>
#include <SDL_ttf.h>

#include "sdl_widget.h"
#include "sdl_utils.h"

#include "font/font_writer.h"

#include <freerdp/log.h>

#define ARRAYSIZE(x) sizeof(x) / sizeof(x[0])
#define MIN(x, y) ((x) > (y)) ? (y) : (x)

#define TAG CLIENT_TAG("SDL.widget")

static const SDL_Color backgroundcolor = { 0, 0, 0x80, 0xff };
static const SDL_Color labelmouseovercolor = { 0, 0x80, 0, 0x60 };
static const SDL_Color labelbackgroundcolor = { 0x80, 0x40, 0, 0xff };
static const SDL_Color labelhighlightcolor = { 0x80, 0, 0, 0x60 };
static const SDL_Color labelfontcolor = { 0, 0xff, 0, 0xff };
static const SDL_Color buttonbackgroundcolor = { 0x80, 0, 0x40, 0xff };
static const SDL_Color buttonhighlightcolor = { 0x80, 0x80, 0, 0x60 };
static const SDL_Color buttonfontcolor = { 0, 0xff, 0x80, 0xff };
static const Uint32 vpadding = 5;
static const Uint32 hpadding = 10;

bool widget_log_error_ex(Uint32 res, const char* what, const char* file, size_t line,
                         const char* fkt)
{
	static wLog* log = NULL;
	if (!log)
		log = WLog_Get(TAG);
	return sdl_log_error_ex(res, log, what, file, line, fkt);
}

static bool draw_rect(SDL_Renderer* renderer, const SDL_Rect* rect, SDL_Color color)
{
	const int drc = SDL_SetRenderDrawColor(renderer, color.r, color.g, color.b, color.a);
	if (widget_log_error(drc, "SDL_SetRenderDrawColor"))
		return false;

	const int rc = SDL_RenderFillRect(renderer, rect);
	return !widget_log_error(rc, "SDL_RenderFillRect");
}

void widget_free(Widget* w)
{
	const Widget empty = { 0 };
	assert(w);
	SDL_DestroyTexture(w->texture);
	SDL_FreeSurface(w->surface);
	TTF_CloseFont(w->font);
	*w = empty;
}

bool widget_fill(SDL_Renderer* renderer, Widget* w, SDL_Color color)
{
	assert(renderer);
	assert(w);
	return draw_rect(renderer, &w->rect, color);
}

bool widget_init(SDL_Renderer* renderer, Widget* w, const SDL_Rect* rect, bool input)
{
	assert(renderer);
	assert(w);

	w->input = input;
	w->surface = SDL_CreateRGBSurfaceWithFormat(0, rect->w, rect->h, 32, SDL_PIXELFORMAT_BGRA32);
	if (!w->surface)
	{
		widget_log_error(-1, "SDL_CreateRGBSurfaceWithFormat");
		goto fail;
	}

	w->texture = SDL_CreateTextureFromSurface(renderer, w->surface);
	if (!w->texture)
	{
		widget_log_error(-1, "SDL_CreateTextureFromSurface");
		goto fail;
	}

	static char* font = NULL;
	if (!font)
		font = create_and_return_temorary_font();

	w->font = TTF_OpenFont(font, 64);
	if (!w->font)
	{
		widget_log_error(-1, "TTF_OpenFont");
		goto fail;
	}

	w->rect = *rect;

	return true;
fail:
	widget_free(w);
	return false;
}

bool widget_update_text(SDL_Renderer* renderer, Widget* w, const char* text, SDL_Color fgcolor,
                        SDL_Color bgcolor)
{
	assert(renderer);
	assert(w);

	if (!widget_fill(renderer, w, bgcolor))
		return false;

	if (!text)
		return true;

	w->surface = TTF_RenderUTF8_Blended(w->font, text, fgcolor);
	if (!w->surface)
		return !widget_log_error(-1, "TTF_RenderText_Blended");

	w->texture = SDL_CreateTextureFromSurface(renderer, w->surface);
	if (!w->texture)
		return !widget_log_error(-1, "SDL_CreateTextureFromSurface");

	const int rc = SDL_RenderCopy(renderer, w->texture, NULL, &w->rect);
	if (rc < 0)
		return !widget_log_error(rc, "SDL_RenderCopy");
	return true;
}

bool button_highlight(SDL_Renderer* renderer, ButtonState* button)
{
	assert(renderer);
	assert(button);

	return widget_fill(renderer, &button->w, buttonhighlightcolor);
}

ButtonState* button_get_selected(ButtonState* buttons, size_t count,
                                 const SDL_MouseButtonEvent* button)
{
	assert(buttons || (count == 0));
	assert(button);

	const Sint32 x = button->x;
	const Sint32 y = button->y;
	for (size_t i = 0; i < count; i++)
	{
		const ButtonState* cur = &buttons[i];
		const SDL_Rect* r = &cur->w.rect;

		if ((x >= r->x) && (x <= r->x + r->w) && (y >= r->y) && (y <= r->y + r->h))
			return cur;
	}
	return NULL;
}

bool button_update(SDL_Renderer* renderer, ButtonState* button)
{
	assert(renderer);
	assert(button);

	return widget_update_text(renderer, &button->w, button->name, buttonfontcolor,
	                          buttonbackgroundcolor);
}

bool buttons_update(SDL_Renderer* renderer, ButtonState* buttons, size_t count)
{
	assert(renderer);
	assert(buttons || (count == 0));

	for (size_t x = 0; x < count; x++)
	{
		if (!button_update(renderer, &buttons[x]))
			return false;
	}
	return true;
}

bool clear_window(SDL_Renderer* renderer)
{
	assert(renderer);

	const int drc = SDL_SetRenderDrawColor(renderer, backgroundcolor.r, backgroundcolor.g,
	                                       backgroundcolor.b, backgroundcolor.a);
	if (widget_log_error(drc, "SDL_SetRenderDrawColor"))
		return false;

	const int rcls = SDL_RenderClear(renderer);
	return !widget_log_error(rcls, "SDL_RenderClear");
}

bool button_init(SDL_Renderer* renderer, ButtonState* button, const char* label, int id,
                 const SDL_Rect* rect)
{
	assert(renderer);
	assert(button);
	assert(label);
	assert(rect);

	button->id = id;
	if (!widget_init(renderer, &button->w, rect, false))
		return false;
	button->name = strdup(label);
	if (!button->name)
		return false;
	return widget_update_text(renderer, &button->w, button->name, buttonfontcolor,
	                          buttonbackgroundcolor);
}

void buttons_free(ButtonState* buttons, size_t count)
{
	const ButtonState empty = { 0 };
	for (size_t x = 0; x < count; x++)
	{
		ButtonState* button = &buttons[x];
		free(button->name);
		widget_free(&button->w);

		*button = empty;
	}
}

bool buttons_init(SDL_Renderer* renderer, size_t count, ButtonState* buttons, const char** labels,
                  const int* ids, Sint32 offsetY, Sint32 width, Sint32 heigth)
{
	assert(count > 0);
	assert(buttons);
	assert(labels);
	assert(ids);
	assert(renderer);

	for (size_t x = 0; x < count; x++)
	{
		const SDL_Rect rect = {
			.y = offsetY, .x = x * (width + hpadding), .h = heigth, .w = width
		};
		if (!button_init(renderer, &buttons[x], labels[x], ids[x], &rect))
			return false;
	}
	return true;
}
