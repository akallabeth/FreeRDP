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

#include "sdl_select.h"
#include "sdl_widget.h"

#define ARRAYSIZE(x) sizeof(x) / sizeof(x[0])
#define MIN(x, y) ((x) > (y)) ? (y) : (x)

typedef struct
{
	char* text;
	Widget label;
} TextInputState;

static const SDL_Color labelmouseovercolor = { 0, 0x80, 0, 0x60 };
static const SDL_Color labelbackgroundcolor = { 0x80, 0x40, 0, 0xff };
static const SDL_Color labelhighlightcolor = { 0x80, 0, 0, 0x60 };
static const SDL_Color labelfontcolor = { 0, 0xff, 0, 0xff };

static const Uint32 vpadding = 5;
static const Uint32 hpadding = 10;

static void text_input_state_free(TextInputState* state)
{
	const TextInputState empty = { 0 };
	assert(state);

	free(state->text);
	widget_free(&state->label);
	*state = empty;
}

static bool text_input_state_init(SDL_Renderer* renderer, TextInputState* state, const char* label,
                                  size_t offset, size_t width, size_t height)
{
	assert(renderer);
	assert(state);

	if (label)
	{
		state->text = strdup(label);
		if (!state->text)
			goto fail;
	}

	const SDL_Rect lrect = { .w = width, .h = height, .x = 0, .y = offset * (height + vpadding) };
	return widget_init(renderer, &state->label, &lrect, false);
fail:
	text_input_state_free(state);
	return false;
}

static void text_input_states_free(TextInputState* states, size_t count)
{
	assert(states || (count == 0));
	for (size_t x = 0; x < count; x++)
	{
		text_input_state_free(&states[x]);
	}
	free(states);
}

static TextInputState* text_input_states_new(SDL_Renderer* renderer, size_t count,
                                             const char* labels[], size_t width, size_t height)
{
	TextInputState* states = calloc(count, sizeof(TextInputState));
	if (!states)
		return NULL;

	for (size_t x = 0; x < count; x++)
	{
		if (!text_input_state_init(renderer, &states[x], labels[x], x, width, height))
			goto fail;
	}
	return states;
fail:
	text_input_states_free(states, count);
	return NULL;
}

static bool text_label_state_fill(SDL_Renderer* renderer, TextInputState* state, SDL_Color color)
{
	assert(renderer);
	assert(state);

	return widget_fill(renderer, &state->label, color);
}

static bool text_input_highlight(SDL_Renderer* renderer, TextInputState* state, bool mouseOver)
{
	assert(renderer);
	assert(state);

	return widget_fill(renderer, &state->label,
	                   mouseOver ? labelmouseovercolor : labelhighlightcolor);
}

static bool text_input_text_update(SDL_Renderer* renderer, TextInputState* state)
{
	assert(renderer);
	assert(state);

	return widget_update_text(renderer, &state->label, state->text, labelfontcolor,
	                          labelbackgroundcolor);
}

static ssize_t text_input_get_index(const TextInputState* state, size_t count,
                                    const SDL_MouseButtonEvent* button)
{
	assert(state || (count == 0));
	assert(button);

	const Sint32 x = button->x;
	const Sint32 y = button->y;
	for (size_t i = 0; i < count; i++)
	{
		const TextInputState* cur = &state[i];
		const SDL_Rect* r = &cur->label.rect;

		if ((x >= r->x) && (x <= r->x + r->w) && (y >= r->y) && (y <= r->y + r->h))
			return i;
	}
	return -1;
}

static bool text_input_states_update(SDL_Renderer* renderer, TextInputState* states, size_t count)
{
	assert(renderer);
	assert(states || (count == 0));

	for (size_t x = 0; x < count; x++)
	{
		TextInputState* state = &states[x];
		if (!text_input_text_update(renderer, state))
			return false;
	}

	return true;
}

int sdl_select_get(const char* title, Uint32 count, const char* labels[])
{
	enum
	{
		INPUT_BUTTON_ACCEPT = 0,
		INPUT_BUTTON_CANCEL = -2
	};
	int res = -1;
	SDL_Renderer* renderer = NULL;
	TextInputState* inputs = NULL;
	ssize_t CurrentActiveTextInput = 0;
	ButtonState buttons[2] = { 0 };
	const int buttonids[2] = { INPUT_BUTTON_ACCEPT, INPUT_BUTTON_CANCEL };
	const char* buttonlabels[2] = { "accept", "cancel" };

	TTF_Init();

	const size_t widget_height = 50;
	const size_t widget_width = 600;

	const size_t total_height = count * (widget_height + vpadding) + vpadding;
	SDL_Window* ecran = SDL_CreateWindow(title, SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
	                                     widget_width, total_height + widget_height, 0);
	if (ecran == NULL)
	{
		widget_log_error(-1, "SDL_CreateWindow");
		goto fail;
	}

	renderer = SDL_CreateRenderer(ecran, -1, SDL_RENDERER_ACCELERATED);
	if (renderer == NULL)
	{
		widget_log_error(-1, "SDL_CreateRenderer");
		goto fail;
	}

	const int rc = SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_ADD);
	if (widget_log_error(rc, "SDL_SetRenderDrawBlendMode"))
		goto fail;

	inputs = text_input_states_new(renderer, count, labels, widget_width, widget_height);
	if (!inputs)
		goto fail;

	if (!buttons_init(renderer, ARRAYSIZE(buttons), buttons, buttonlabels, buttonids, total_height,
	                  widget_width / 2, widget_height))
		goto fail;

	bool running = true;
	while (running)
	{
		if (!clear_window(renderer))
			goto fail;

		if (!text_input_states_update(renderer, inputs, count))
			goto fail;

		if (!buttons_update(renderer, buttons, ARRAYSIZE(buttons)))
			goto fail;

		SDL_Event event = { 0 };
		SDL_WaitEvent(&event);
		switch (event.type)
		{
			case SDL_KEYDOWN:
				switch (event.key.keysym.sym)
				{
					case SDLK_UP:
					case SDLK_BACKSPACE:
						if (CurrentActiveTextInput > 0)
							CurrentActiveTextInput--;
						else
							CurrentActiveTextInput = count - 1;
						break;
					case SDLK_DOWN:
					case SDLK_TAB:
						if (CurrentActiveTextInput < 0)
							CurrentActiveTextInput = 0;
						else
							CurrentActiveTextInput++;
						CurrentActiveTextInput = CurrentActiveTextInput % count;
						break;
					case SDLK_RETURN:
					case SDLK_RETURN2:
					case SDLK_KP_ENTER:
						running = false;
						res = CurrentActiveTextInput;
						break;
					case SDLK_ESCAPE:
						running = false;
						res = INPUT_BUTTON_CANCEL;
						break;
					default:
						break;
				}
				break;
			case SDL_MOUSEMOTION:
			{
				ssize_t TextInputIndex = text_input_get_index(inputs, count, &event.button);
				if (TextInputIndex >= 0)
				{
					TextInputState* state = &inputs[TextInputIndex];
					if (!text_input_highlight(renderer, state, true))
						goto fail;
				}

				ButtonState* button =
				    button_get_selected(buttons, ARRAYSIZE(buttons), &event.button);
				if (button)
				{
					if (!button_highlight(renderer, button))
						goto fail;
				}
			}
			break;
			case SDL_MOUSEBUTTONDOWN:
			{
				ButtonState* button =
				    button_get_selected(buttons, ARRAYSIZE(buttons), &event.button);
				if (button)
				{
					running = false;
					if (button->id == INPUT_BUTTON_CANCEL)
						res = INPUT_BUTTON_CANCEL;
					else
						res = CurrentActiveTextInput;
				}
				else
				{
					CurrentActiveTextInput = text_input_get_index(inputs, count, &event.button);
				}
			}
			break;
			case SDL_QUIT:
				res = INPUT_BUTTON_CANCEL;
				running = false;
				break;
			default:
				break;
		}

		if (CurrentActiveTextInput >= 0)
		{
			TextInputState* state = &inputs[CurrentActiveTextInput];
			if (!text_input_highlight(renderer, state, false))
				goto fail;
		}

		SDL_RenderPresent(renderer);
	}

fail:
	if (inputs)
		text_input_states_free(inputs, count);

	buttons_free(buttons, ARRAYSIZE(buttons));

	SDL_DestroyWindow(ecran);
	SDL_DestroyRenderer(renderer);
	TTF_Quit();

	return res;
}
