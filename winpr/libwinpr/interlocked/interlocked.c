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

#include <winpr/config.h>

#include <winpr/assert.h>
#include <winpr/wlog.h>
#include <winpr/platform.h>
#include <winpr/synch.h>
#include <winpr/handle.h>

#include <winpr/interlocked.h>

/* Singly-Linked List */

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>

LONG InterlockedIncrement(LONG volatile* Addend)
{
	WINPR_ASSERT(Addend);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_add_and_fetch(Addend, 1);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

LONG InterlockedDecrement(LONG volatile* Addend)
{
	WINPR_ASSERT(Addend);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_sub_and_fetch(Addend, 1);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

LONG InterlockedExchange(LONG volatile* Target, LONG Value)
{
	WINPR_ASSERT(Target);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_val_compare_and_swap(Target, *Target, Value);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

LONG InterlockedExchangeAdd(LONG volatile* Addend, LONG Value)
{
	WINPR_ASSERT(Addend);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_fetch_and_add(Addend, Value);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

LONG InterlockedCompareExchange(LONG volatile* Destination, LONG Exchange, LONG Comperand)
{
	WINPR_ASSERT(Destination);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

PVOID InterlockedCompareExchangePointer(PVOID volatile* Destination, PVOID Exchange,
                                        PVOID Comperand)
{
	WINPR_ASSERT(Destination);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

#endif /* _WIN32 */

#if defined(_WIN32) && !defined(WINPR_INTERLOCKED_COMPARE_EXCHANGE64)

/* InterlockedCompareExchange64 already defined */

#elif defined(_WIN32) && defined(WINPR_INTERLOCKED_COMPARE_EXCHANGE64)

static volatile HANDLE mutex = nullptr;

BOOL static_mutex_lock(volatile HANDLE* static_mutex)
{
	if (*static_mutex == nullptr)
	{
		HANDLE handle;

		if (!(handle = CreateMutex(nullptr, FALSE, nullptr)))
			return FALSE;

		if (InterlockedCompareExchangePointer((PVOID*)static_mutex, (PVOID)handle, nullptr) !=
		    nullptr)
			(void)CloseHandle(handle);
	}

	return (WaitForSingleObject(*static_mutex, INFINITE) == WAIT_OBJECT_0);
}

LONGLONG InterlockedCompareExchange64(LONGLONG volatile* Destination, LONGLONG Exchange,
                                      LONGLONG Comperand)
{
	LONGLONG previousValue = 0;
	BOOL locked = static_mutex_lock(&mutex);

	previousValue = *Destination;

	if (*Destination == Comperand)
		*Destination = Exchange;

	if (locked)
		(void)ReleaseMutex(mutex);
	else
		(void)fprintf(stderr,
		              "WARNING: InterlockedCompareExchange64 operation might have failed\n");

	return previousValue;
}

#elif (defined(ANDROID) && ANDROID) || \
    (defined(__GNUC__) && !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8))

#include <pthread.h>

static pthread_mutex_t mutex;

LONGLONG InterlockedCompareExchange64(LONGLONG volatile* Destination, LONGLONG Exchange,
                                      LONGLONG Comperand)
{
	LONGLONG previousValue = 0;

	pthread_mutex_lock(&mutex);

	previousValue = *Destination;

	if (*Destination == Comperand)
		*Destination = Exchange;

	pthread_mutex_unlock(&mutex);

	return previousValue;
}

#else

LONGLONG InterlockedCompareExchange64(LONGLONG volatile* Destination, LONGLONG Exchange,
                                      LONGLONG Comperand)
{
	WINPR_ASSERT(Destination);

#if defined(__GNUC__) || defined(__clang__)
	WINPR_PRAGMA_DIAG_PUSH
	WINPR_PRAGMA_DIAG_IGNORED_ATOMIC_SEQ_CST
	return __sync_val_compare_and_swap(Destination, Comperand, Exchange);
	WINPR_PRAGMA_DIAG_POP
#else
	return 0;
#endif
}

#endif
