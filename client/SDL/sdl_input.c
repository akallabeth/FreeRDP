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

#include "sdl_input.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <SDL.h>
#include <SDL_ttf.h>

#include "sdl_widget.h"

#define ARRAYSIZE(x) sizeof(x) / sizeof(x[0])
#define MIN(x, y) ((x) > (y)) ? (y) : (x)

typedef struct
{
	Uint32 flags;
	size_t capacity;
	char* text;
	char* text_label;
	Widget label;
	Widget input;
} TextInputState;

static const SDL_Color inputbackgroundcolor = { 0x80, 0, 0, 0xff };
static const SDL_Color inputhighlightcolor = { 0x80, 0, 0, 0x60 };
static const SDL_Color inputmouseovercolor = { 0, 0x80, 0, 0x60 };
static const SDL_Color inputfontcolor = { 0, 0xff, 0, 0xff };
static const SDL_Color labelbackgroundcolor = { 0x80, 0x40, 0, 0xff };
static const SDL_Color labelfontcolor = { 0, 0xff, 0, 0xff };
static const Uint32 vpadding = 5;
static const Uint32 hpadding = 10;

static void text_input_state_free(TextInputState* state)
{
	const TextInputState empty = { 0 };
	assert(state);

	free(state->text_label);
	free(state->text);
	widget_free(&state->input);
	widget_free(&state->label);
	*state = empty;
}

static bool text_input_state_init(SDL_Renderer* renderer, TextInputState* state, const char* label,
                                  const char* initial, Uint32 flags, size_t offset, size_t width,
                                  size_t height)
{
	assert(renderer);
	assert(state);

	state->flags = flags;
	if (label)
	{
		state->text_label = strdup(label);
		if (!state->text_label)
			goto fail;
	}

	if (initial)
	{
		state->capacity = strlen(initial) + 1;
		state->text = strdup(initial);
		if (!state->text)
			goto fail;
	}
	const SDL_Rect irect = {
		.w = width, .h = height, .x = width + hpadding, .y = offset * (height + vpadding)
	};
	if (!widget_init(renderer, &state->input, &irect, true))
		goto fail;

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
                                             const char* labels[], const char* initial[],
                                             const Uint32 flags[], size_t width, size_t height)
{
	TextInputState* states = calloc(count, sizeof(TextInputState));
	if (!states)
		return NULL;

	for (size_t x = 0; x < count; x++)
	{
		if (!text_input_state_init(renderer, &states[x], labels[x], initial[x], flags[x], x, width,
		                           height))
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

	return widget_fill(renderer, &state->input,
	                   mouseOver ? inputmouseovercolor : inputhighlightcolor);
}

static bool text_input_text_resize(TextInputState* state, size_t size)
{
	assert(state);

	const size_t length = strnlen(state->text, state->capacity);
	char* tmp = realloc(state->text, size);
	if (!tmp && (size > 0))
		return false;
	if (size > state->capacity)
	{
		memset(&tmp[length], 0, size - length);
	}
	state->capacity = size;
	state->text = tmp;

	return true;
}

static bool text_input_text_update(SDL_Renderer* renderer, TextInputState* state)
{
	assert(renderer);
	assert(state);

	if (!widget_update_text(renderer, &state->label, state->text_label, labelfontcolor,
	                        labelbackgroundcolor))
		return false;

	char* text = NULL;
	if (state->text)
	{
		text = SDL_strdup(state->text);
		if (!text)
			return false;
		if (state->flags & SDL_INPUT_MASK)
			memset(text, '*', strlen(text));
	}
	bool rc =
	    widget_update_text(renderer, &state->input, text, inputfontcolor, inputbackgroundcolor);
	free(text);
	return rc;
}

static bool text_input_remove_str(SDL_Renderer* renderer, TextInputState* state, size_t count)
{
	assert(renderer);
	assert(state);

	size_t length = strnlen(state->text, state->capacity);
	if (length > 0)
	{
		length -= MIN(count, length);
		state->text[length] = '\0';
	}
	return text_input_text_update(renderer, state);
}

static bool text_input_append_str(SDL_Renderer* renderer, TextInputState* state, const char* text,
                                  size_t len)
{
	assert(renderer);
	assert(state);

	size_t length = strnlen(state->text, state->capacity);
	if (length + len >= state->capacity)
	{
		if (!text_input_text_resize(state, state->capacity + len + 32))
			return false;
	}

	strncat(state->text, text, len);

	return text_input_text_update(renderer, state);
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
		const SDL_Rect* r = &cur->input.rect;

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

int sdl_input_get(const char* title, Uint32 count, const char* labels[], const char* initial[],
                  const Uint32 flags[], char* result[])
{
	enum
	{
		INPUT_BUTTON_ACCEPT = 1,
		INPUT_BUTTON_CANCEL = -2
	};
	int res = -1;
	SDL_Renderer* renderer = NULL;
	TextInputState* inputs = NULL;
	ssize_t LastActiveTextInput = -1;
	ssize_t CurrentActiveTextInput = 0;
	ButtonState buttons[2] = { 0 };
	const int buttonids[2] = { INPUT_BUTTON_ACCEPT, INPUT_BUTTON_CANCEL };
	const char* buttonlabels[2] = { "accept", "cancel" };

	TTF_Init();

	const size_t widget_width = 300;
	const size_t widget_heigth = 50;

	const size_t total_width = widget_width + widget_width;
	const size_t input_height = count * (widget_heigth + vpadding) + vpadding;
	const size_t total_height = input_height + widget_heigth;
	SDL_Window* ecran = SDL_CreateWindow(title, SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
	                                     total_width, total_height, 0);
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

	inputs =
	    text_input_states_new(renderer, count, labels, initial, flags, widget_width, widget_heigth);
	if (!inputs)
		goto fail;

	if (!buttons_init(renderer, ARRAYSIZE(buttons), buttons, buttonlabels, buttonids, input_height,
	                  widget_width, widget_heigth))
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
					case SDLK_BACKSPACE:
						if (CurrentActiveTextInput >= 0)
						{
							TextInputState* input = &inputs[CurrentActiveTextInput];
							if (!text_input_remove_str(renderer, input, 1))
								goto fail;
						}
						break;
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
						res = INPUT_BUTTON_ACCEPT;
						break;
					case SDLK_ESCAPE:
						running = false;
						res = INPUT_BUTTON_CANCEL;
						break;
					default:
						break;
				}
				break;
			case SDL_TEXTINPUT:
				if (CurrentActiveTextInput >= 0)
				{
					TextInputState* input = &inputs[CurrentActiveTextInput];
					if (!text_input_append_str(renderer, input, event.text.text,
					                           strnlen(event.text.text, sizeof(event.text.text))))
						goto fail;
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
				CurrentActiveTextInput = text_input_get_index(inputs, count, &event.button);

				ButtonState* button =
				    button_get_selected(buttons, ARRAYSIZE(buttons), &event.button);
				if (button)
				{
					running = false;
					if (button->id == INPUT_BUTTON_CANCEL)
						res = INPUT_BUTTON_CANCEL;
					else
						res = INPUT_BUTTON_ACCEPT;
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

		if (LastActiveTextInput != CurrentActiveTextInput)
		{
			if (CurrentActiveTextInput < 0)
				SDL_StopTextInput();
			else
				SDL_StartTextInput();
			LastActiveTextInput = CurrentActiveTextInput;
		}

		if (CurrentActiveTextInput >= 0)
		{
			TextInputState* state = &inputs[CurrentActiveTextInput];
			if (!text_input_highlight(renderer, state, false))
				goto fail;
		}

		SDL_RenderPresent(renderer);
	}

	for (size_t x = 0; x < count; x++)
	{
		TextInputState* state = &inputs[x];
		const char* val = state->text;
		if (val)
		{
			result[x] = SDL_strdup(val);
		}
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
