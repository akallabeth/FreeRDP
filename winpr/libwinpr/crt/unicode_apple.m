/**
 * WinPR: Windows Portable Runtime
 * Unicode Conversion (CRT)
 *
 * Copyright 2022 Armin Novak <anovak@thincast.com>
 * Copyright 2022 Thincast Technologies GmbH
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

#import <Foundation/Foundation.h>

#include <winpr/config.h>
#include <winpr/assert.h>

#include <errno.h>
#include <wctype.h>

#include <winpr/crt.h>
#include <winpr/error.h>
#include <winpr/print.h>

#ifndef MIN
#define MIN(a, b) (a) < (b) ? (a) : (b)
#endif

#include "../log.h"
#define TAG WINPR_TAG("unicode")

int int_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                            LPWSTR lpWideCharStr, int cchWideChar)
{
	BOOL addNullTerminator = FALSE;

	/* If cbMultiByte is 0, the function fails */
	if ((cbMultiByte == 0) || (cbMultiByte < -1))
		return 0;

	/* If cbMultiByte is -1, the string is null-terminated */
	if (cbMultiByte == -1)
	{
		size_t len = strnlen((const char *)lpMultiByteStr, INT32_MAX);
		if (len >= INT32_MAX)
			return 0;
		cbMultiByte = (int)len;
		addNullTerminator = TRUE;
	}
	else
	{
		const size_t len = strnlen(lpMultiByteStr, (size_t)cbMultiByte);
		addNullTerminator = len < (size_t)cbMultiByte; /* If len == cbMultiByte no '\0' was found */
	}

	NSString *utf = [[NSString alloc] initWithBytes:lpMultiByteStr
	                                         length:cbMultiByte
	                                       encoding:NSUTF8StringEncoding];
	if (!utf)
		return -1;

	const WCHAR *utf16 = (const WCHAR *)[utf cStringUsingEncoding:NSUTF16StringEncoding];
	if (!utf16)
		return -1;

	if (cchWideChar == 0)
		cchWideChar = _wcslen(utf16);
	else
	{
		const size_t len = _wcsnlen(utf16, (size_t)cchWideChar);
		memcpy(lpWideCharStr, utf16, len * sizeof(WCHAR));
		if ((len < (size_t)cchWideChar) && (len > 0) && (lpWideCharStr[len - 1] != '\0'))
			lpWideCharStr[len] = '\0';
		cchWideChar = (int)len;
	}
	if (addNullTerminator)
		cchWideChar++;
	return cchWideChar;
}

int int_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
                            LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar,
                            LPBOOL lpUsedDefaultChar)
{
	BOOL addNullTerminator = FALSE;

	/* If cchWideChar is 0, the function fails */
	if ((cchWideChar == 0) || (cchWideChar < -1))
		return 0;

	/* If cchWideChar is -1, the string is null-terminated */
	if (cchWideChar == -1)
	{
		size_t len = _wcslen(lpWideCharStr);
		if (len >= INT32_MAX)
			return 0;
		cchWideChar = (int)len;
		addNullTerminator = TRUE;
	}
	else
	{
		const size_t len = _wcsnlen(lpWideCharStr, (size_t)cchWideChar);
		addNullTerminator = len < (size_t)cchWideChar; /* If len == cchWideChar no '\0' was found */
	}

	NSString *utf = [[NSString alloc] initWithCharacters:lpWideCharStr length:cchWideChar];
	if (!utf)
		return -1;

	const char *utf8 = [utf cStringUsingEncoding:NSUTF8StringEncoding];
	if (!utf8)
		return -1;

	if (cbMultiByte == 0)
		cbMultiByte = strlen(utf8);
	else
	{
		const size_t len = strnlen(utf8, (size_t)cbMultiByte);
		memcpy(lpMultiByteStr, utf8, len * sizeof(char));
		if ((len < (size_t)cbMultiByte) && (len > 0) && (lpMultiByteStr[len - 1] != '\0'))
			lpMultiByteStr[len] = '\0';
		cbMultiByte = (int)len;
	}
	if (addNullTerminator)
		cbMultiByte++;

	return cbMultiByte;
}
