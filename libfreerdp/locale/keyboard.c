/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Keyboard Localization
 *
 * Copyright 2009-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <winpr/crt.h>

#include <freerdp/types.h>
#include <freerdp/locale/keyboard.h>
#include <freerdp/locale/locale.h>

#include "liblocale.h"

#if defined(__MACOSX__)
#include "keyboard_apple.h"
#endif

#ifdef WITH_X11

#include "keyboard_x11.h"

#ifdef WITH_XKBFILE
#include "keyboard_xkbfile.h"
#endif

#endif

static DWORD VIRTUAL_SCANCODE_TO_X11_KEYCODE[256][2] = { 0 };
static DWORD X11_KEYCODE_TO_VIRTUAL_SCANCODE[256] = { 0 };
static DWORD REMAPPING_TABLE[0x10000] = { 0 };

static int freerdp_detect_keyboard(DWORD* keyboardLayoutId)
{
#if defined(_WIN32)
	CHAR name[KL_NAMELENGTH + 1] = { 0 };
	if (GetKeyboardLayoutNameA(name))
	{
		ULONG rc;

		errno = 0;
		rc = strtoul(name, NULL, 16);
		if (errno == 0)
			*keyboardLayoutId = rc;
	}

	if (*keyboardLayoutId == 0)
		*keyboardLayoutId = ((DWORD)GetKeyboardLayout(0) >> 16) & 0x0000FFFF;
#endif

#if defined(__MACOSX__)
	if (*keyboardLayoutId == 0)
		freerdp_detect_keyboard_layout_from_cf(keyboardLayoutId);
#endif

#ifdef WITH_X11
	if (*keyboardLayoutId == 0)
		freerdp_detect_keyboard_layout_from_xkb(keyboardLayoutId);
#endif

	if (*keyboardLayoutId == 0)
		freerdp_detect_keyboard_layout_from_system_locale(keyboardLayoutId);

	if (*keyboardLayoutId == 0)
		*keyboardLayoutId = ENGLISH_UNITED_STATES;

	return 0;
}

static int freerdp_keyboard_init_apple(DWORD* keyboardLayoutId,
                                       DWORD x11_keycode_to_rdp_scancode[256])
{
	DWORD vkcode;
	DWORD keycode;
	DWORD keycode_to_vkcode[256];

	ZeroMemory(keycode_to_vkcode, sizeof(keycode_to_vkcode));

	for (keycode = 0; keycode < 256; keycode++)
	{
		vkcode = keycode_to_vkcode[keycode] =
		    GetVirtualKeyCodeFromKeycode(keycode, KEYCODE_TYPE_APPLE);
		x11_keycode_to_rdp_scancode[keycode] = GetVirtualScanCodeFromVirtualKeyCode(vkcode, 4);
	}

	return 0;
}

static int freerdp_keyboard_init_x11_evdev(DWORD* keyboardLayoutId,
                                           DWORD x11_keycode_to_rdp_scancode[256])
{
	DWORD vkcode;
	DWORD keycode;
	DWORD keycode_to_vkcode[256];

	ZeroMemory(keycode_to_vkcode, sizeof(keycode_to_vkcode));

	for (keycode = 0; keycode < 256; keycode++)
	{
		vkcode = keycode_to_vkcode[keycode] =
		    GetVirtualKeyCodeFromKeycode(keycode, KEYCODE_TYPE_EVDEV);
		x11_keycode_to_rdp_scancode[keycode] = GetVirtualScanCodeFromVirtualKeyCode(vkcode, 4);
	}

	return 0;
}

DWORD freerdp_keyboard_init(DWORD keyboardLayoutId)
{
	DWORD keycode;
#if defined(__APPLE__) || defined(WITH_X11) || defined(WITH_WAYLAND)
	int status = -1;
#endif

#ifdef __APPLE__
	if (status < 0)
		status = freerdp_keyboard_init_apple(&keyboardLayoutId, X11_KEYCODE_TO_VIRTUAL_SCANCODE);
#endif

#if defined(WITH_X11) || defined(WITH_WAYLAND)

#ifdef WITH_XKBFILE
	if (status < 0)
		status = freerdp_keyboard_init_xkbfile(&keyboardLayoutId, X11_KEYCODE_TO_VIRTUAL_SCANCODE);
#endif

	if (status < 0)
		status =
		    freerdp_keyboard_init_x11_evdev(&keyboardLayoutId, X11_KEYCODE_TO_VIRTUAL_SCANCODE);

#endif

	freerdp_detect_keyboard(&keyboardLayoutId);

	ZeroMemory(VIRTUAL_SCANCODE_TO_X11_KEYCODE, sizeof(VIRTUAL_SCANCODE_TO_X11_KEYCODE));

	for (keycode = 0; keycode < ARRAYSIZE(VIRTUAL_SCANCODE_TO_X11_KEYCODE); keycode++)
	{
		VIRTUAL_SCANCODE_TO_X11_KEYCODE
		[RDP_SCANCODE_CODE(X11_KEYCODE_TO_VIRTUAL_SCANCODE[keycode])]
		    [RDP_SCANCODE_EXTENDED(X11_KEYCODE_TO_VIRTUAL_SCANCODE[keycode]) ? 1 : 0] = keycode;
	}

	return keyboardLayoutId;
}

DWORD freerdp_keyboard_init_ex(DWORD keyboardLayoutId, const char* keyboardRemappingList)
{
	DWORD res = freerdp_keyboard_init(keyboardLayoutId);

	memset(REMAPPING_TABLE, 0, sizeof(REMAPPING_TABLE));
	if (keyboardRemappingList)
	{
		char* copy = _strdup(keyboardRemappingList);
		char* context = NULL;
		char* token;
		if (!copy)
			goto fail;
		token = strtok_s(copy, ",", &context);
		while (token)
		{
			DWORD key, value;
			int rc = sscanf(token, "%" PRIu32 "=%" PRIu32, &key, &value);
			if (rc != 2)
				rc = sscanf(token, "%" PRIx32 "=%" PRIx32 "", &key, &value);
			if (rc != 2)
				rc = sscanf(token, "%" PRIu32 "=%" PRIx32, &key, &value);
			if (rc != 2)
				rc = sscanf(token, "%" PRIx32 "=%" PRIu32, &key, &value);
			if (rc != 2)
				goto fail;
			if (key >= ARRAYSIZE(REMAPPING_TABLE))
				goto fail;
			REMAPPING_TABLE[key] = value;
			token = strtok_s(NULL, ",", &context);
		}
	fail:
		free(copy);
	}
	return res;
}

DWORD freerdp_keyboard_get_rdp_scancode_from_x11_keycode(DWORD keycode)
{
	const DWORD scancode = X11_KEYCODE_TO_VIRTUAL_SCANCODE[keycode];
	const DWORD remapped = REMAPPING_TABLE[scancode];
	DEBUG_KBD("x11 keycode: %02" PRIX32 " -> rdp code: [%04" PRIx16 "] %02" PRIX8 "%s", keycode,
	          scancode, RDP_SCANCODE_CODE(scancode),
	          RDP_SCANCODE_EXTENDED(scancode) ? " extended" : "");

	if (remapped != 0)
	{
		DEBUG_KBD("remapped scancode: [%04" PRIx16 "] %02" PRIX8 "[%s] -> [%04" PRIx16 "] %02" PRIX8
		          "[%s]",
		          scancode, RDP_SCANCODE_CODE(scancode),
		          RDP_SCANCODE_EXTENDED(scancode) ? " extended" : "", remapped,
		          RDP_SCANCODE_CODE(remapped), RDP_SCANCODE_EXTENDED(remapped) ? " extended" : "");
		return remapped;
	}
	return scancode;
}

DWORD freerdp_keyboard_get_x11_keycode_from_rdp_scancode(DWORD scancode, BOOL extended)
{
	if (extended)
		return VIRTUAL_SCANCODE_TO_X11_KEYCODE[scancode][1];
	else
		return VIRTUAL_SCANCODE_TO_X11_KEYCODE[scancode][0];
}

#define ENTRYSIZE 53
typedef struct
{
	char buffer[ENTRYSIZE];
} scancode_map_t;

static scancode_map_t scancode_map[0x200] = { 0 };

static const char* freerdp_scancode_to_name(DWORD scancode)
{
	switch (scancode)
	{
		case RDP_SCANCODE_ESCAPE:
			return "RDP_SCANCODE_ESCAPE";
		case RDP_SCANCODE_KEY_1:
			return "RDP_SCANCODE_KEY_1";
		case RDP_SCANCODE_KEY_2:
			return "RDP_SCANCODE_KEY_2";
		case RDP_SCANCODE_KEY_3:
			return "RDP_SCANCODE_KEY_3";
		case RDP_SCANCODE_KEY_4:
			return "RDP_SCANCODE_KEY_4";
		case RDP_SCANCODE_KEY_5:
			return "RDP_SCANCODE_KEY_5";
		case RDP_SCANCODE_KEY_6:
			return "RDP_SCANCODE_KEY_6";
		case RDP_SCANCODE_KEY_7:
			return "RDP_SCANCODE_KEY_7";
		case RDP_SCANCODE_KEY_8:
			return "RDP_SCANCODE_KEY_8";
		case RDP_SCANCODE_KEY_9:
			return "RDP_SCANCODE_KEY_9";
		case RDP_SCANCODE_KEY_0:
			return "RDP_SCANCODE_KEY_0";
		case RDP_SCANCODE_OEM_MINUS:
			return "RDP_SCANCODE_OEM_MINUS";
		case RDP_SCANCODE_OEM_PLUS:
			return "RDP_SCANCODE_OEM_PLUS";
		case RDP_SCANCODE_BACKSPACE:
			return "RDP_SCANCODE_BACKSPACE";
		case RDP_SCANCODE_TAB:
			return "RDP_SCANCODE_TAB";
		case RDP_SCANCODE_KEY_Q:
			return "RDP_SCANCODE_KEY_Q";
		case RDP_SCANCODE_KEY_W:
			return "RDP_SCANCODE_KEY_W";
		case RDP_SCANCODE_KEY_E:
			return "RDP_SCANCODE_KEY_E";
		case RDP_SCANCODE_KEY_R:
			return "RDP_SCANCODE_KEY_R";
		case RDP_SCANCODE_KEY_T:
			return "RDP_SCANCODE_KEY_T";
		case RDP_SCANCODE_KEY_Y:
			return "RDP_SCANCODE_KEY_Y";
		case RDP_SCANCODE_KEY_U:
			return "RDP_SCANCODE_KEY_U";
		case RDP_SCANCODE_KEY_I:
			return "RDP_SCANCODE_KEY_I";
		case RDP_SCANCODE_KEY_O:
			return "RDP_SCANCODE_KEY_O";
		case RDP_SCANCODE_KEY_P:
			return "RDP_SCANCODE_KEY_P";
		case RDP_SCANCODE_OEM_4:
			return "RDP_SCANCODE_OEM_4";
		case RDP_SCANCODE_OEM_6:
			return "RDP_SCANCODE_OEM_6";
		case RDP_SCANCODE_RETURN:
			return "RDP_SCANCODE_RETURN";
		case RDP_SCANCODE_LCONTROL:
			return "RDP_SCANCODE_LCONTROL";
		case RDP_SCANCODE_KEY_A:
			return "RDP_SCANCODE_KEY_A";
		case RDP_SCANCODE_KEY_S:
			return "RDP_SCANCODE_KEY_S";
		case RDP_SCANCODE_KEY_D:
			return "RDP_SCANCODE_KEY_D";
		case RDP_SCANCODE_KEY_F:
			return "RDP_SCANCODE_KEY_F";
		case RDP_SCANCODE_KEY_G:
			return "RDP_SCANCODE_KEY_G";
		case RDP_SCANCODE_KEY_H:
			return "RDP_SCANCODE_KEY_H";
		case RDP_SCANCODE_KEY_J:
			return "RDP_SCANCODE_KEY_J";
		case RDP_SCANCODE_KEY_K:
			return "RDP_SCANCODE_KEY_K";
		case RDP_SCANCODE_KEY_L:
			return "RDP_SCANCODE_KEY_L";
		case RDP_SCANCODE_OEM_1:
			return "RDP_SCANCODE_OEM_1";
		case RDP_SCANCODE_OEM_7:
			return "RDP_SCANCODE_OEM_7";
		case RDP_SCANCODE_OEM_3:
			return "RDP_SCANCODE_OEM_3";
		case RDP_SCANCODE_LSHIFT:
			return "RDP_SCANCODE_LSHIFT";
		case RDP_SCANCODE_OEM_5:
			return "RDP_SCANCODE_OEM_5";
		case RDP_SCANCODE_KEY_Z:
			return "RDP_SCANCODE_KEY_Z";
		case RDP_SCANCODE_KEY_X:
			return "RDP_SCANCODE_KEY_X";
		case RDP_SCANCODE_KEY_C:
			return "RDP_SCANCODE_KEY_C";
		case RDP_SCANCODE_KEY_V:
			return "RDP_SCANCODE_KEY_V";
		case RDP_SCANCODE_KEY_B:
			return "RDP_SCANCODE_KEY_B";
		case RDP_SCANCODE_KEY_N:
			return "RDP_SCANCODE_KEY_N";
		case RDP_SCANCODE_KEY_M:
			return "RDP_SCANCODE_KEY_M";
		case RDP_SCANCODE_OEM_COMMA:
			return "RDP_SCANCODE_OEM_COMMA";
		case RDP_SCANCODE_OEM_PERIOD:
			return "RDP_SCANCODE_OEM_PERIOD";
		case RDP_SCANCODE_OEM_2:
			return "RDP_SCANCODE_OEM_2";
		case RDP_SCANCODE_RSHIFT:
			return "RDP_SCANCODE_RSHIFT";
		case RDP_SCANCODE_MULTIPLY:
			return "RDP_SCANCODE_MULTIPLY";
		case RDP_SCANCODE_LMENU:
			return "RDP_SCANCODE_LMENU";
		case RDP_SCANCODE_SPACE:
			return "RDP_SCANCODE_SPACE";
		case RDP_SCANCODE_CAPSLOCK:
			return "RDP_SCANCODE_CAPSLOCK";
		case RDP_SCANCODE_F1:
			return "RDP_SCANCODE_F1";
		case RDP_SCANCODE_F2:
			return "RDP_SCANCODE_F2";
		case RDP_SCANCODE_F3:
			return "RDP_SCANCODE_F3";
		case RDP_SCANCODE_F4:
			return "RDP_SCANCODE_F4";
		case RDP_SCANCODE_F5:
			return "RDP_SCANCODE_F5";
		case RDP_SCANCODE_F6:
			return "RDP_SCANCODE_F6";
		case RDP_SCANCODE_F7:
			return "RDP_SCANCODE_F7";
		case RDP_SCANCODE_F8:
			return "RDP_SCANCODE_F8";
		case RDP_SCANCODE_F9:
			return "RDP_SCANCODE_F9";
		case RDP_SCANCODE_F10:
			return "RDP_SCANCODE_F10";
		case RDP_SCANCODE_NUMLOCK:
			return "RDP_SCANCODE_NUMLOCK";
		case RDP_SCANCODE_SCROLLLOCK:
			return "RDP_SCANCODE_SCROLLLOCK";
		case RDP_SCANCODE_NUMPAD7:
			return "RDP_SCANCODE_NUMPAD7";
		case RDP_SCANCODE_NUMPAD8:
			return "RDP_SCANCODE_NUMPAD8";
		case RDP_SCANCODE_NUMPAD9:
			return "RDP_SCANCODE_NUMPAD9";
		case RDP_SCANCODE_SUBTRACT:
			return "RDP_SCANCODE_SUBTRACT";
		case RDP_SCANCODE_NUMPAD4:
			return "RDP_SCANCODE_NUMPAD4";
		case RDP_SCANCODE_NUMPAD5:
			return "RDP_SCANCODE_NUMPAD5";
		case RDP_SCANCODE_NUMPAD6:
			return "RDP_SCANCODE_NUMPAD6";
		case RDP_SCANCODE_ADD:
			return "RDP_SCANCODE_ADD";
		case RDP_SCANCODE_NUMPAD1:
			return "RDP_SCANCODE_NUMPAD1";
		case RDP_SCANCODE_NUMPAD2:
			return "RDP_SCANCODE_NUMPAD2";
		case RDP_SCANCODE_NUMPAD3:
			return "RDP_SCANCODE_NUMPAD3";
		case RDP_SCANCODE_NUMPAD0:
			return "RDP_SCANCODE_NUMPAD0";
		case RDP_SCANCODE_DECIMAL:
			return "RDP_SCANCODE_DECIMAL";
		case RDP_SCANCODE_SYSREQ:
			return "RDP_SCANCODE_SYSREQ";
		case RDP_SCANCODE_OEM_102:
			return "RDP_SCANCODE_OEM_102";
		case RDP_SCANCODE_F11:
			return "RDP_SCANCODE_F11";
		case RDP_SCANCODE_F12:
			return "RDP_SCANCODE_F12";
		case RDP_SCANCODE_SLEEP:
			return "RDP_SCANCODE_SLEEP";
		case RDP_SCANCODE_ZOOM:
			return "RDP_SCANCODE_ZOOM";
		case RDP_SCANCODE_HELP:
			return "RDP_SCANCODE_HELP";
		case RDP_SCANCODE_F13:
			return "RDP_SCANCODE_F13";
		case RDP_SCANCODE_F14:
			return "RDP_SCANCODE_F14";
		case RDP_SCANCODE_F15:
			return "RDP_SCANCODE_F15";
		case RDP_SCANCODE_F16:
			return "RDP_SCANCODE_F16";
		case RDP_SCANCODE_F17:
			return "RDP_SCANCODE_F17";
		case RDP_SCANCODE_F18:
			return "RDP_SCANCODE_F18";
		case RDP_SCANCODE_F19:
			return "RDP_SCANCODE_F19";
		case RDP_SCANCODE_F20:
			return "RDP_SCANCODE_F20";
		case RDP_SCANCODE_F21:
			return "RDP_SCANCODE_F21";
		case RDP_SCANCODE_F22:
			return "RDP_SCANCODE_F22";
		case RDP_SCANCODE_F23:
			return "RDP_SCANCODE_F23";
		case RDP_SCANCODE_F24:
			return "RDP_SCANCODE_F24";
		case RDP_SCANCODE_HIRAGANA:
			return "RDP_SCANCODE_HIRAGANA";
		case RDP_SCANCODE_ABNT_C1:
			return "RDP_SCANCODE_ABNT_C1";
		case RDP_SCANCODE_F24_JP:
			return "RDP_SCANCODE_F24_JP";
		case RDP_SCANCODE_CONVERT_JP:
			return "RDP_SCANCODE_CONVERT_JP";
		case RDP_SCANCODE_NONCONVERT_JP:
			return "RDP_SCANCODE_NONCONVERT_JP";
		case RDP_SCANCODE_TAB_JP:
			return "RDP_SCANCODE_TAB_JP";
		case RDP_SCANCODE_BACKSLASH_JP:
			return "RDP_SCANCODE_BACKSLASH_JP";
		case RDP_SCANCODE_ABNT_C2:
			return "RDP_SCANCODE_ABNT_C2";
		case RDP_SCANCODE_HANJA:
			return "RDP_SCANCODE_HANJA";
		case RDP_SCANCODE_HANGUL:
			return "RDP_SCANCODE_HANGUL";
		case RDP_SCANCODE_RETURN_KP:
			return "RDP_SCANCODE_RETURN_KP";
		case RDP_SCANCODE_RCONTROL:
			return "RDP_SCANCODE_RCONTROL";
		case RDP_SCANCODE_DIVIDE:
			return "RDP_SCANCODE_DIVIDE";
		case RDP_SCANCODE_PRINTSCREEN:
			return "RDP_SCANCODE_PRINTSCREEN";
		case RDP_SCANCODE_RMENU:
			return "RDP_SCANCODE_RMENU";
		case RDP_SCANCODE_PAUSE:
			return "RDP_SCANCODE_PAUSE";
		case RDP_SCANCODE_HOME:
			return "RDP_SCANCODE_HOME";
		case RDP_SCANCODE_UP:
			return "RDP_SCANCODE_UP";
		case RDP_SCANCODE_PRIOR:
			return "RDP_SCANCODE_PRIOR";
		case RDP_SCANCODE_LEFT:
			return "RDP_SCANCODE_LEFT";
		case RDP_SCANCODE_RIGHT:
			return "RDP_SCANCODE_RIGHT";
		case RDP_SCANCODE_END:
			return "RDP_SCANCODE_END";
		case RDP_SCANCODE_DOWN:
			return "RDP_SCANCODE_DOWN";
		case RDP_SCANCODE_NEXT:
			return "RDP_SCANCODE_NEXT";
		case RDP_SCANCODE_INSERT:
			return "RDP_SCANCODE_INSERT";
		case RDP_SCANCODE_DELETE:
			return "RDP_SCANCODE_DELETE";
		case RDP_SCANCODE_NULL:
			return "RDP_SCANCODE_NULL";
		case RDP_SCANCODE_HELP2:
			return "RDP_SCANCODE_HELP2";
		case RDP_SCANCODE_LWIN:
			return "RDP_SCANCODE_LWIN";
		case RDP_SCANCODE_RWIN:
			return "RDP_SCANCODE_RWIN";
		case RDP_SCANCODE_APPS:
			return "RDP_SCANCODE_APPS";
		case RDP_SCANCODE_POWER_JP:
			return "RDP_SCANCODE_POWER_JP";
		case RDP_SCANCODE_SLEEP_JP:
			return "RDP_SCANCODE_SLEEP_JP";
		case RDP_SCANCODE_NUMLOCK_EXTENDED:
			return "RDP_SCANCODE_NUMLOCK_EXTENDED";
		case RDP_SCANCODE_RSHIFT_EXTENDED:
			return "RDP_SCANCODE_RSHIFT_EXTENDED";
		case RDP_SCANCODE_VOLUME_MUTE:
			return "RDP_SCANCODE_VOLUME_MUTE";
		case RDP_SCANCODE_VOLUME_DOWN:
			return "RDP_SCANCODE_VOLUME_DOWN";
		case RDP_SCANCODE_VOLUME_UP:
			return "RDP_SCANCODE_VOLUME_UP";
		case RDP_SCANCODE_MEDIA_NEXT_TRACK:
			return "RDP_SCANCODE_MEDIA_NEXT_TRACK";
		case RDP_SCANCODE_MEDIA_PREV_TRACK:
			return "RDP_SCANCODE_MEDIA_PREV_TRACK";
		case RDP_SCANCODE_MEDIA_STOP:
			return "RDP_SCANCODE_MEDIA_STOP";
		case RDP_SCANCODE_MEDIA_PLAY_PAUSE:
			return "RDP_SCANCODE_MEDIA_PLAY_PAUSE";
		case RDP_SCANCODE_BROWSER_BACK:
			return "RDP_SCANCODE_BROWSER_BACK";
		case RDP_SCANCODE_BROWSER_FORWARD:
			return "RDP_SCANCODE_BROWSER_FORWARD";
		case RDP_SCANCODE_BROWSER_REFRESH:
			return "RDP_SCANCODE_BROWSER_REFRESH";
		case RDP_SCANCODE_BROWSER_STOP:
			return "RDP_SCANCODE_BROWSER_STOP";
		case RDP_SCANCODE_BROWSER_SEARCH:
			return "RDP_SCANCODE_BROWSER_SEARCH";
		case RDP_SCANCODE_BROWSER_FAVORITES:
			return "RDP_SCANCODE_BROWSER_FAVORITES";
		case RDP_SCANCODE_BROWSER_HOME:
			return "RDP_SCANCODE_BROWSER_HOME";
		case RDP_SCANCODE_LAUNCH_MAIL:
			return "RDP_SCANCODE_LAUNCH_MAIL";
		case RDP_SCANCODE_LAUNCH_MEDIA_SELECT:
			return "RDP_SCANCODE_LAUNCH_MEDIA_SELECT";
		case RDP_SCANCODE_LAUNCH_APP1:
			return "RDP_SCANCODE_LAUNCH_APP1";
		case RDP_SCANCODE_LAUNCH_APP2:
			return "RDP_SCANCODE_LAUNCH_APP2";
		default:
			return "RDP_SCANCODE_UNKNOWN";
	}
}

const char* freerdp_scancode_to_string(DWORD scancode)
{
	scancode_map_t* entry;
	WINPR_ASSERT(scancode < ARRAYSIZE(scancode_map));

	entry = &scancode_map[scancode];
	if (strnlen(entry->buffer, ARRAYSIZE(entry->buffer)) == 0)
	{
		int rc =
		    _snprintf(entry->buffer, ARRAYSIZE(entry->buffer),
		              "%-032s [0x%04" PRIx16 ", ext=%-05s]", freerdp_scancode_to_name(scancode),
		              scancode, RDP_SCANCODE_EXTENDED(scancode) ? "true" : "false");
		WINPR_ASSERT(rc > 0);
		WINPR_ASSERT(rc < ARRAYSIZE(entry->buffer));
	}
	return entry->buffer;
}
