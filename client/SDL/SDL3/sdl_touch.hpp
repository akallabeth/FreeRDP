/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP SDL touch/mouse input
 *
 * Copyright 2022 Armin Novak <armin.novak@thincast.com>
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

#pragma once

#include <winpr/wtypes.h>

#include <SDL3/SDL.h>
#include "sdl_types.hpp"

/** @brief scale coordinates to RDP
 *
 *  @param sdl A pointer to the client context
 *  @param windowId the window the event originated from
 *  @param point Coordinates in (window) relative coordinates
 *  @param abosolute If \b true the window/monitor offset to the top/left of the RDP virtual screen
 * is added, if \b false only the values are scaled.
 *
 *  return A point in RDP virtual screen absolute coordinates
 */
SDL_Point sdl_scale_event(SdlContext* sdl, Uint32 windowId, const SDL_Point& point,
                          bool absolute = true);

BOOL sdl_scale_coordinates(SdlContext* sdl, Uint32 windowId, INT32* px, INT32* py,
                           BOOL fromLocalToRDP, BOOL applyOffset);

BOOL sdl_handle_mouse_motion(SdlContext* sdl, const SDL_MouseMotionEvent* ev);
BOOL sdl_handle_mouse_wheel(SdlContext* sdl, const SDL_MouseWheelEvent* ev);
BOOL sdl_handle_mouse_button(SdlContext* sdl, const SDL_MouseButtonEvent* ev);

BOOL sdl_handle_touch_down(SdlContext* sdl, const SDL_TouchFingerEvent* ev);
BOOL sdl_handle_touch_up(SdlContext* sdl, const SDL_TouchFingerEvent* ev);
BOOL sdl_handle_touch_motion(SdlContext* sdl, const SDL_TouchFingerEvent* ev);
