/**
 * WinPR: Windows Portable Runtime
 * Interlocked Singly-Linked Lists
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

#ifndef WINPR_INTERLOCKED_H
#define WINPR_INTERLOCKED_H

#include <winpr/config.h>
#include <winpr/spec.h>
#include <winpr/platform.h>
#include <winpr/winpr.h>
#include <winpr/wtypes.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _WIN32

	WINPR_API LONG InterlockedIncrement(LONG volatile* Addend);

	WINPR_API LONG InterlockedDecrement(LONG volatile* Addend);

	WINPR_ATTR_NODISCARD
	WINPR_API LONG InterlockedExchange(LONG volatile* Target, LONG Value);

	WINPR_ATTR_NODISCARD
	WINPR_API LONG InterlockedExchangeAdd(LONG volatile* Addend, LONG Value);

	WINPR_ATTR_NODISCARD
	WINPR_API LONG InterlockedCompareExchange(LONG volatile* Destination, LONG Exchange,
	                                          LONG Comperand);

	WINPR_ATTR_NODISCARD
	WINPR_API PVOID InterlockedCompareExchangePointer(PVOID volatile* Destination, PVOID Exchange,
	                                                  PVOID Comperand);

#else /* _WIN32 */
#define WINPR_LIST_ENTRY LIST_ENTRY
#define WINPR_PLIST_ENTRY PLIST_ENTRY

#define WINPR_SINGLE_LIST_ENTRY SINGLE_LIST_ENTRY
#define WINPR_PSINGLE_LIST_ENTRY PSINGLE_LIST_ENTRY

#define WINPR_SLIST_ENTRY SLIST_ENTRY
#define WINPR_PSLIST_ENTRY PSLIST_ENTRY

#define WINPR_SLIST_HEADER SLIST_HEADER
#define WINPR_PSLIST_HEADER PSLIST_HEADER

#endif /* _WIN32 */

#if (!defined(_WIN32) || \
     (defined(_WIN32) && (_WIN32_WINNT < 0x0502) && !defined(InterlockedCompareExchange64)))
#define WINPR_INTERLOCKED_COMPARE_EXCHANGE64 1
#endif

#ifdef WINPR_INTERLOCKED_COMPARE_EXCHANGE64

	WINPR_ATTR_NODISCARD
	WINPR_API LONGLONG InterlockedCompareExchange64(LONGLONG volatile* Destination,
	                                                LONGLONG Exchange, LONGLONG Comperand);

#endif

#ifdef __cplusplus
}
#endif

#endif /* WINPR_INTERLOCKED_H */
