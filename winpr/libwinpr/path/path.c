/**
 * WinPR: Windows Portable Runtime
 * Path Functions
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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
#include <winpr/version.h>
#include <winpr/build-config.h>

#include <winpr/crt.h>
#include <winpr/tchar.h>

#include <winpr/path.h>
#include <winpr/file.h>

#include "../utils.h"
#include "path.h"

#if defined(WITH_CWALK)
#include <cwalk.h>
#endif

#ifndef PATHCCH_MAX_CCH
#define PATHCCH_MAX_CCH 0x8000
#endif

static const char PATH_SLASH_CHR = '/';
static const char PATH_SLASH_STR[] = "/";

static const char PATH_BACKSLASH_CHR = '\\';

#ifdef _WIN32
static const char PATH_BACKSLASH_STR[] = "\\";
static const WCHAR PATH_BACKSLASH_STR_W[] = L"\\";
static const WCHAR PATH_SLASH_CHR_W = L'/';
static const WCHAR PATH_BACKSLASH_CHR_W = L'\\';
static const WCHAR PATH_SLASH_STR_W[] = L"/";
#else
#if defined(__BIG_ENDIAN__)
static const WCHAR PATH_SLASH_CHR_W = 0x2f00;
static const WCHAR PATH_BACKSLASH_CHR_W = 0x5c00;
static const WCHAR PATH_SLASH_STR_W[] = { 0x2f00, '\0' };
#else
static const WCHAR PATH_SLASH_CHR_W = '/';
static const WCHAR PATH_BACKSLASH_CHR_W = '\\';
static const WCHAR PATH_SLASH_STR_W[] = { '/', '\0' };
#endif

#endif

#ifdef _WIN32
#define PATH_SEPARATOR_CHR PATH_BACKSLASH_CHR
#define PATH_SEPARATOR_STR PATH_BACKSLASH_STR
#define PATH_SEPARATOR_CHR_W PATH_BACKSLASH_CHR_W
#define PATH_SEPARATOR_STR_W PATH_BACKSLASH_STR_W
#else
#define PATH_SEPARATOR_CHR PATH_SLASH_CHR
#define PATH_SEPARATOR_STR PATH_SLASH_STR
#define PATH_SEPARATOR_CHR_W PATH_SLASH_CHR_W
#define PATH_SEPARATOR_STR_W PATH_SLASH_STR_W
#endif

/* Unix-style Paths */

#define DEFINE_UNICODE FALSE
#define CUR_PATH_SEPARATOR_CHR PATH_SLASH_CHR
#define PATH_CCH_ADD_EXTENSION UnixPathCchAddExtensionA
#include "include/PathCchAddExtension.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef PATH_CCH_ADD_EXTENSION

#define DEFINE_UNICODE TRUE
#define CUR_PATH_SEPARATOR_CHR PATH_SLASH_CHR_W
#define PATH_CCH_ADD_EXTENSION UnixPathCchAddExtensionW
#include "include/PathCchAddExtension.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef PATH_CCH_ADD_EXTENSION

/* Native-style Paths */

#define DEFINE_UNICODE FALSE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR
#define PATH_CCH_ADD_EXTENSION NativePathCchAddExtensionA
#include "include/PathCchAddExtension.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef PATH_CCH_ADD_EXTENSION

#define DEFINE_UNICODE TRUE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR_W
#define PATH_CCH_ADD_EXTENSION NativePathCchAddExtensionW
#include "include/PathCchAddExtension.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef PATH_CCH_ADD_EXTENSION

/*
 * PathCchAppend
 */

/* Native-style Paths */

#define DEFINE_UNICODE FALSE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR
#define CUR_PATH_SEPARATOR_STR PATH_SEPARATOR_STR
#define PATH_CCH_APPEND NativePathCchAppendA
#include "include/PathCchAppend.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_CCH_APPEND

#define DEFINE_UNICODE TRUE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR_W
#define CUR_PATH_SEPARATOR_STR PATH_SEPARATOR_STR_W
#define PATH_CCH_APPEND NativePathCchAppendW
#include "include/PathCchAppend.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_CCH_APPEND

#if !defined(_WIN32)

#if !defined(WITH_CWALK)
static void replace(char* str, size_t slen, const char* pattern)
{
	const size_t len = strlen(pattern);
	while (TRUE)
	{
		char* cur = strstr(str, pattern);
		if (!cur)
			return;

		const char* src = &cur[len];
		/* Ensure terminating '\0' is moved as well */
		const size_t rem = strnlen(src, slen) + 1;
		memmove(&cur[1], src, rem);
	}
}

WINPR_ATTR_NODISCARD
static BOOL replace_dotdot(char* str, size_t slen)
{
	const char pattern[] = "/../";
	const size_t len = strlen(pattern);
	while (TRUE)
	{
		char* cur = strstr(str, pattern);
		if (!cur)
			return TRUE;

		char* start = cur;
		const char* end = &cur[len];
		while (start > str)
		{
			start--;
			if (*start == '/')
				break;
		}
		if (*start != '/')
			return FALSE;

		/* Ensure terminating '\0' is moved as well */
		const size_t rem = strnlen(end, slen) + 1;
		memmove(&start[1], end, rem);
	}
}

WINPR_ATTR_NODISCARD
static BOOL replace_trailing_dotdot(char* str, size_t slen)
{
	const size_t len = strnlen(str, slen);
	if (len < 3)
		return TRUE;

	if (strcmp(&str[len - 3], "/..") != 0)
		return TRUE;

	char* start = &str[len - 4];
	while (start >= str)
	{
		if (*start == '/')
		{
			start[1] = '\0';
			return TRUE;
		}
		start--;
	}
	return FALSE;
}

#endif

WINPR_ATTR_NODISCARD
char* winpr_PathCanonicalize(const char* path)
{
	WINPR_ASSERT(path);

	const size_t len = strlen(path);
#if defined(WITH_CWALK)
	char* str = calloc(len + 1, sizeof(char));
	if (!str)
		return nullptr;
	(void)cwk_path_normalize(path, str, len + 1);
	return str;
#else
	char* str = strndup(path, len);
	if (!str)
		return nullptr;
	replace(str, len, "/./");
	replace(str, len, "//");
	if (!replace_dotdot(str, len) || !replace_trailing_dotdot(str, len))
	{
		free(str);
		return nullptr;
	}

	size_t slen = 0;
	while ((slen = strnlen(str, len)) > 1)
	{
		if ((str[slen - 1] == '.') || (str[slen - 1] == '/'))
			str[slen - 1] = '\0';
		else
			break;
	}

	return str;
#endif
}

#endif

/* Unix-style Paths */

#define DEFINE_UNICODE FALSE
#define CUR_PATH_SEPARATOR_CHR PATH_SLASH_CHR
#define CUR_PATH_SEPARATOR_STR PATH_SLASH_STR
#define PATH_ALLOC_COMBINE UnixPathAllocCombineA
#include "include/PathAllocCombine.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_ALLOC_COMBINE

#define DEFINE_UNICODE TRUE
#define CUR_PATH_SEPARATOR_CHR PATH_SLASH_CHR_W
#define CUR_PATH_SEPARATOR_STR PATH_SLASH_STR_W
#define PATH_ALLOC_COMBINE UnixPathAllocCombineW
#include "include/PathAllocCombine.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_ALLOC_COMBINE

/* Native-style Paths */

#define DEFINE_UNICODE FALSE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR
#define CUR_PATH_SEPARATOR_STR PATH_SEPARATOR_STR
#define PATH_ALLOC_COMBINE NativePathAllocCombineA
#include "include/PathAllocCombine.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_ALLOC_COMBINE

#define DEFINE_UNICODE TRUE
#define CUR_PATH_SEPARATOR_CHR PATH_SEPARATOR_CHR_W
#define CUR_PATH_SEPARATOR_STR PATH_SEPARATOR_STR_W
#define PATH_ALLOC_COMBINE NativePathAllocCombineW
#include "include/PathAllocCombine.h"
#undef DEFINE_UNICODE
#undef CUR_PATH_SEPARATOR_CHR
#undef CUR_PATH_SEPARATOR_STR
#undef PATH_ALLOC_COMBINE

/*
 * Path Portability Functions
 */

/**
 * PathCchConvertStyle
 */

HRESULT PathCchConvertStyleA(PSTR pszPath, size_t cchPath, unsigned long dwFlags)
{
	if (dwFlags == PATH_STYLE_WINDOWS)
	{
		for (size_t index = 0; index < cchPath; index++)
		{
			if (pszPath[index] == PATH_SLASH_CHR)
				pszPath[index] = PATH_BACKSLASH_CHR;
		}
	}
	else if (dwFlags == PATH_STYLE_UNIX)
	{
		for (size_t index = 0; index < cchPath; index++)
		{
			if (pszPath[index] == PATH_BACKSLASH_CHR)
				pszPath[index] = PATH_SLASH_CHR;
		}
	}
	else if (dwFlags == PATH_STYLE_NATIVE)
	{
		if (PATH_SEPARATOR_CHR == PATH_BACKSLASH_CHR)
		{
			/* Unix-style to Windows-style */

			for (size_t index = 0; index < cchPath; index++)
			{
				if (pszPath[index] == PATH_SLASH_CHR)
					pszPath[index] = PATH_BACKSLASH_CHR;
			}
		}
		else if (PATH_SEPARATOR_CHR == PATH_SLASH_CHR)
		{
			/* Windows-style to Unix-style */

			for (size_t index = 0; index < cchPath; index++)
			{
				if (pszPath[index] == PATH_BACKSLASH_CHR)
					pszPath[index] = PATH_SLASH_CHR;
			}
		}
		else
		{
			/* Unexpected error */
			return E_FAIL;
		}
	}
	else
	{
		/* Gangnam style? */
		return E_FAIL;
	}

	return S_OK;
}

HRESULT PathCchConvertStyleW(PWSTR pszPath, size_t cchPath, unsigned long dwFlags)
{
	if (dwFlags == PATH_STYLE_WINDOWS)
	{
		for (size_t index = 0; index < cchPath; index++)
		{
			if (pszPath[index] == PATH_SLASH_CHR_W)
				pszPath[index] = PATH_BACKSLASH_CHR_W;
		}
	}
	else if (dwFlags == PATH_STYLE_UNIX)
	{
		for (size_t index = 0; index < cchPath; index++)
		{
			if (pszPath[index] == PATH_BACKSLASH_CHR_W)
				pszPath[index] = PATH_SLASH_CHR_W;
		}
	}
	else if (dwFlags == PATH_STYLE_NATIVE)
	{
		if (PATH_SEPARATOR_CHR == PATH_BACKSLASH_CHR_W)
		{
			/* Unix-style to Windows-style */

			for (size_t index = 0; index < cchPath; index++)
			{
				if (pszPath[index] == PATH_SLASH_CHR_W)
					pszPath[index] = PATH_BACKSLASH_CHR_W;
			}
		}
		else if (PATH_SEPARATOR_CHR == PATH_SLASH_CHR_W)
		{
			/* Windows-style to Unix-style */

			for (size_t index = 0; index < cchPath; index++)
			{
				if (pszPath[index] == PATH_BACKSLASH_CHR_W)
					pszPath[index] = PATH_SLASH_CHR_W;
			}
		}
		else
		{
			/* Unexpected error */
			return E_FAIL;
		}
	}
	else
	{
		/* Gangnam style? */
		return E_FAIL;
	}

	return S_OK;
}

/**
 * PathGetSeparator
 */

char PathGetSeparatorA(unsigned long dwFlags)
{
	if (dwFlags == PATH_STYLE_WINDOWS)
		return PATH_BACKSLASH_CHR;
	if (dwFlags == PATH_STYLE_UNIX)
		return PATH_SLASH_CHR;

	return PATH_SEPARATOR_CHR;
}

WCHAR PathGetSeparatorW(unsigned long dwFlags)
{
	if (dwFlags == PATH_STYLE_WINDOWS)
		return PATH_BACKSLASH_CHR_W;
	if (dwFlags == PATH_STYLE_UNIX)
		return PATH_SLASH_CHR_W;

	return PATH_SEPARATOR_CHR;
}

/**
 * PathGetSharedLibraryExtension
 */
static const CHAR SharedLibraryExtensionDllA[] = "dll";
static const CHAR SharedLibraryExtensionSoA[] = "so";
static const CHAR SharedLibraryExtensionDylibA[] = "dylib";

static const CHAR SharedLibraryExtensionDotDllA[] = ".dll";
static const CHAR SharedLibraryExtensionDotSoA[] = ".so";
static const CHAR SharedLibraryExtensionDotDylibA[] = ".dylib";
PCSTR PathGetSharedLibraryExtensionA(unsigned long dwFlags)
{
	if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT)
	{
		if (dwFlags & PATH_SHARED_LIB_EXT_WITH_DOT)
		{
			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DLL)
				return SharedLibraryExtensionDotDllA;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_SO)
				return SharedLibraryExtensionDotSoA;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DYLIB)
				return SharedLibraryExtensionDotDylibA;
		}
		else
		{
			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DLL)
				return SharedLibraryExtensionDllA;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_SO)
				return SharedLibraryExtensionSoA;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DYLIB)
				return SharedLibraryExtensionDylibA;
		}
	}

	if (dwFlags & PATH_SHARED_LIB_EXT_WITH_DOT)
	{
#ifdef _WIN32
		return SharedLibraryExtensionDotDllA;
#elif defined(__APPLE__)
		if (dwFlags & PATH_SHARED_LIB_EXT_APPLE_SO)
			return SharedLibraryExtensionDotSoA;
		else
			return SharedLibraryExtensionDotDylibA;
#else
		return SharedLibraryExtensionDotSoA;
#endif
	}
	else
	{
#ifdef _WIN32
		return SharedLibraryExtensionDllA;
#elif defined(__APPLE__)
		if (dwFlags & PATH_SHARED_LIB_EXT_APPLE_SO)
			return SharedLibraryExtensionSoA;
		else
			return SharedLibraryExtensionDylibA;
#else
		return SharedLibraryExtensionSoA;
#endif
	}
}

PCWSTR PathGetSharedLibraryExtensionW(unsigned long dwFlags)
{
	static WCHAR buffer[6][16] = WINPR_C_ARRAY_INIT;
	const WCHAR* SharedLibraryExtensionDotDllW = InitializeConstWCharFromUtf8(
	    SharedLibraryExtensionDotDllA, buffer[0], ARRAYSIZE(buffer[0]));
	const WCHAR* SharedLibraryExtensionDotSoW =
	    InitializeConstWCharFromUtf8(SharedLibraryExtensionDotSoA, buffer[1], ARRAYSIZE(buffer[1]));
	const WCHAR* SharedLibraryExtensionDotDylibW = InitializeConstWCharFromUtf8(
	    SharedLibraryExtensionDotDylibA, buffer[2], ARRAYSIZE(buffer[2]));
	const WCHAR* SharedLibraryExtensionDllW =
	    InitializeConstWCharFromUtf8(SharedLibraryExtensionDllA, buffer[3], ARRAYSIZE(buffer[3]));
	const WCHAR* SharedLibraryExtensionSoW =
	    InitializeConstWCharFromUtf8(SharedLibraryExtensionSoA, buffer[4], ARRAYSIZE(buffer[4]));
	const WCHAR* SharedLibraryExtensionDylibW =
	    InitializeConstWCharFromUtf8(SharedLibraryExtensionDylibA, buffer[5], ARRAYSIZE(buffer[5]));

	if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT)
	{
		if (dwFlags & PATH_SHARED_LIB_EXT_WITH_DOT)
		{
			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DLL)
				return SharedLibraryExtensionDotDllW;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_SO)
				return SharedLibraryExtensionDotSoW;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DYLIB)
				return SharedLibraryExtensionDotDylibW;
		}
		else
		{
			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DLL)
				return SharedLibraryExtensionDllW;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_SO)
				return SharedLibraryExtensionSoW;

			if (dwFlags & PATH_SHARED_LIB_EXT_EXPLICIT_DYLIB)
				return SharedLibraryExtensionDylibW;
		}
	}

	if (dwFlags & PATH_SHARED_LIB_EXT_WITH_DOT)
	{
#ifdef _WIN32
		return SharedLibraryExtensionDotDllW;
#elif defined(__APPLE__)
		if (dwFlags & PATH_SHARED_LIB_EXT_APPLE_SO)
			return SharedLibraryExtensionDotSoW;
		else
			return SharedLibraryExtensionDotDylibW;
#else
		return SharedLibraryExtensionDotSoW;
#endif
	}
	else
	{
#ifdef _WIN32
		return SharedLibraryExtensionDllW;
#elif defined(__APPLE__)
		if (dwFlags & PATH_SHARED_LIB_EXT_APPLE_SO)
			return SharedLibraryExtensionSoW;
		else
			return SharedLibraryExtensionDylibW;
#else
		return SharedLibraryExtensionSoW;
#endif
	}
}

const char* GetKnownPathIdString(int id)
{
	switch (id)
	{
		case KNOWN_PATH_HOME:
			return "KNOWN_PATH_HOME";
		case KNOWN_PATH_TEMP:
			return "KNOWN_PATH_TEMP";
		case KNOWN_PATH_XDG_DATA_HOME:
			return "KNOWN_PATH_XDG_DATA_HOME";
		case KNOWN_PATH_XDG_CONFIG_HOME:
			return "KNOWN_PATH_XDG_CONFIG_HOME";
		case KNOWN_PATH_XDG_CACHE_HOME:
			return "KNOWN_PATH_XDG_CACHE_HOME";
		case KNOWN_PATH_XDG_RUNTIME_DIR:
			return "KNOWN_PATH_XDG_RUNTIME_DIR";
		case KNOWN_PATH_SYSTEM_CONFIG_HOME:
			return "KNOWN_PATH_SYSTEM_CONFIG_HOME";
		default:
			return "KNOWN_PATH_UNKNOWN_ID";
	}
}

static char* concat(const char* path, size_t pathlen, const char* name, size_t namelen)
{
	const size_t strsize = pathlen + namelen + 2;
	char* str = calloc(strsize, sizeof(char));
	if (!str)
		return nullptr;

	winpr_str_append(path, str, strsize, "");
	winpr_str_append(name, str, strsize, "");
	return str;
}

BOOL winpr_RemoveDirectory_RecursiveA(LPCSTR lpPathName)
{
	BOOL ret = FALSE;

	if (!lpPathName)
		return FALSE;

	const size_t pathnamelen = strlen(lpPathName);
	const size_t path_slash_len = pathnamelen + 3;
	char* path_slash = calloc(pathnamelen + 4, sizeof(char));
	if (!path_slash)
		return FALSE;
	strncat(path_slash, lpPathName, pathnamelen);

	const char star[] = "*";
	const HRESULT hr = NativePathCchAppendA(path_slash, path_slash_len, star);
	HANDLE dir = INVALID_HANDLE_VALUE;
	if (FAILED(hr))
		goto fail;

	{
		WIN32_FIND_DATAA findFileData = WINPR_C_ARRAY_INIT;
		dir = FindFirstFileA(path_slash, &findFileData);

		if (dir == INVALID_HANDLE_VALUE)
			goto fail;

		ret = TRUE;
		path_slash[path_slash_len - 1] = '\0'; /* remove trailing '*' */
		do
		{
			const size_t len = strnlen(findFileData.cFileName, ARRAYSIZE(findFileData.cFileName));

			if ((len == 1 && findFileData.cFileName[0] == '.') ||
			    (len == 2 && findFileData.cFileName[0] == '.' && findFileData.cFileName[1] == '.'))
			{
				continue;
			}

			char* fullpath = concat(path_slash, path_slash_len, findFileData.cFileName, len);
			if (!fullpath)
				goto fail;

			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				ret = winpr_RemoveDirectory_RecursiveA(fullpath);
			else
			{
				WINPR_PRAGMA_DIAG_PUSH
				WINPR_PRAGMA_DIAG_IGNORED_DEPRECATED_DECL
				ret = winpr_DeleteFile(fullpath);
				WINPR_PRAGMA_DIAG_POP
			}

			free(fullpath);

			if (!ret)
				break;
		} while (ret && FindNextFileA(dir, &findFileData) != 0);
	}

	if (ret)
	{
		if (!winpr_RemoveDirectory(lpPathName))
			ret = FALSE;
	}

fail:
	FindClose(dir);
	free(path_slash);
	return ret;
}

BOOL winpr_RemoveDirectory_RecursiveW(LPCWSTR lpPathName)
{
	char* name = ConvertWCharToUtf8Alloc(lpPathName, nullptr);
	if (!name)
		return FALSE;
	const BOOL rc = winpr_RemoveDirectory_RecursiveA(name);
	free(name);
	return rc;
}

char* winpr_GetConfigFilePathVA(BOOL system, WINPR_FORMAT_ARG const char* filename, va_list ap)
{
	eKnownPathTypes id = system ? KNOWN_PATH_SYSTEM_CONFIG_HOME : KNOWN_PATH_XDG_CONFIG_HOME;
	const char* vendor = winpr_getApplicationDetailsVendor();
	const char* product = winpr_getApplicationDetailsProduct();
	const SSIZE_T version = winpr_getApplicationDetailsVersion();

	if (!vendor || !product)
		return nullptr;

	char* config = GetKnownSubPathV(id, "%s", vendor);
	if (!config)
		return nullptr;

	char* base = nullptr;
	if (version < 0)
		base = GetCombinedPathV(config, "%s", product);
	else
		base = GetCombinedPathV(config, "%s%" PRIdz, product, version);
	free(config);

	if (!base)
		return nullptr;
	char* path = GetCombinedPathVA(base, filename, ap);
	free(base);

	return path;
}

char* winpr_GetConfigFilePath(BOOL system, const char* filename)
{
	if (!filename)
		return winpr_GetConfigFilePathV(system, "%s", "");
	return winpr_GetConfigFilePathV(system, "%s", filename);
}

char* winpr_GetConfigFilePathV(BOOL system, const char* filename, ...)
{
	va_list ap = WINPR_C_ARRAY_INIT;
	va_start(ap, filename);
	char* str = winpr_GetConfigFilePathVA(system, filename, ap);
	va_end(ap);
	return str;
}
