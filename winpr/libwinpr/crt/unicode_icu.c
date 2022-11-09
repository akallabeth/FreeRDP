/**
 * WinPR: Windows Portable Runtime
 * Unicode Conversion (CRT)
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <unicode/ucnv.h>
#include <unicode/ustring.h>

#include "../log.h"
#define TAG WINPR_TAG("unicode")

int int_MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                            LPWSTR lpWideCharStr, int cchWideChar)
{
	size_t charLen = 0;
	LPWSTR targetStart;

	WINPR_UNUSED(dwFlags);

	/* If cbMultiByte is 0, the function fails */

	if ((cbMultiByte == 0) || (cbMultiByte < -1))
		return 0;

	/* If cbMultiByte is -1, the string is null-terminated */

	if (cbMultiByte == -1)
		charLen = strlen(lpMultiByteStr);
	else if (cbMultiByte < 0)
	{
		return -1;
	}
	else
		charLen = strnlen(lpMultiByteStr, (size_t)cbMultiByte);

	if (charLen >= INT32_MAX)
		return 0;

	/*
	 * if cchWideChar is 0, the function returns the required buffer size
	 * in characters for lpWideCharStr and makes no use of the output parameter itself.
	 */
	{
		UErrorCode error;
		int32_t targetLength;
		int32_t targetCapacity;

		switch (CodePage)
		{
			case CP_ACP:
			case CP_UTF8:
				break;

			default:
				WLog_ERR(TAG, "Unsupported encoding %u", CodePage);
				return 0;
		}

		targetStart = lpWideCharStr;
		targetCapacity = cchWideChar;
		error = U_ZERO_ERROR;

		if (cchWideChar == 0)
			u_strFromUTF8(NULL, 0, &targetLength, lpMultiByteStr, cbMultiByte, &error);
		else
		{
			u_strFromUTF8(targetStart, targetCapacity, &targetLength, lpMultiByteStr, cbMultiByte,
			              &error);
			switch (error)
			{
				default:
					cchWideChar = targetLength;
					break;
			}
		}
	}
	if ((cchWideChar > 0) && (charLen == (size_t)cchWideChar))
		cchWideChar++;

	return cchWideChar;
}

int int_WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
                            LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar,
                            LPBOOL lpUsedDefaultChar)
{
	char* targetStart;

	/* If cchWideChar is 0, the function fails */

	if ((cchWideChar == 0) || (cchWideChar < -1))
		return 0;

	/* If cchWideChar is -1, the string is null-terminated */

	if (cchWideChar == -1)
	{
		size_t len = _wcslen(lpWideCharStr);
		if (len >= INT32_MAX)
			return 0;
		cchWideChar = (int)len + 1;
	}

	/*
	 * if cbMultiByte is 0, the function returns the required buffer size
	 * in bytes for lpMultiByteStr and makes no use of the output parameter itself.
	 */
	{
		UErrorCode error;
		int32_t targetLength;
		int32_t targetCapacity;

		switch (CodePage)
		{
			case CP_ACP:
			case CP_UTF8:
				break;

			default:
				WLog_ERR(TAG, "Unsupported encoding %u", CodePage);
				return 0;
		}

		targetStart = lpMultiByteStr;
		targetCapacity = cbMultiByte;
		error = U_ZERO_ERROR;

		if (cbMultiByte == 0)
		{
			u_strToUTF8(NULL, 0, &targetLength, lpWideCharStr, cchWideChar, &error);
			cbMultiByte = targetLength;
		}
		else
		{
			u_strToUTF8(targetStart, targetCapacity, &targetLength, lpWideCharStr, cchWideChar,
			            &error);
			cbMultiByte = U_SUCCESS(error) ? targetLength : 0;
		}
	}
	return cbMultiByte;
}
