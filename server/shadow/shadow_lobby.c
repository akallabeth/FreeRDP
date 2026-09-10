/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <freerdp/config.h>

#include <winpr/assert.h>
#include <winpr/cast.h>

#include "shadow.h"

#include "shadow_lobby.h"

BOOL shadow_client_init_lobby(rdpShadowServer* server)
{
	BOOL rc = FALSE;
	RECTANGLE_16 invalidRect = WINPR_C_ARRAY_INIT;

	WINPR_ASSERT(server);
	rdpShadowSurface* lobby = server->lobby;

	if (!lobby)
		return FALSE;

	EnterCriticalSection(&lobby->lock);

	invalidRect.left = 0;
	invalidRect.top = 0;
	WINPR_ASSERT(lobby->width <= UINT16_MAX);
	WINPR_ASSERT(lobby->height <= UINT16_MAX);
	invalidRect.right = (UINT16)lobby->width;
	invalidRect.bottom = (UINT16)lobby->height;
	if (server->shareSubRect)
	{
		/* If we have shared sub rect setting, only fill shared rect */
		if (!rectangles_intersection(&invalidRect, &(server->subRect), &invalidRect))
			goto fail;
	}

	if (!region16_union_rect(&(lobby->invalidRegion), &(lobby->invalidRegion), &invalidRect))
		goto fail;

	rc = TRUE;
fail:
	LeaveCriticalSection(&lobby->lock);
	return rc;
}
