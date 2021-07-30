/*
 * WinPR: Windows Portable Runtime
 * BitStream Utils
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

#ifndef WINPR_UTILS_BITSTREAM_H
#define WINPR_UTILS_BITSTREAM_H

#include <winpr/winpr.h>
#include <winpr/wtypes.h>
#include <winpr/assert.h>

#include <winpr/crt.h>
#include <winpr/wlog.h>

struct _wBitStream
{
	BYTE reserved[100];
};

typedef struct _wBitStream wBitStream;

#define BITDUMP_MSB_FIRST 0x00000001
#define BITDUMP_STDERR 0x00000002

#ifdef __cplusplus
extern "C"
{
#endif

	WINPR_API void BitStream_Prefetch(wBitStream* _bs);
	WINPR_API void BitStream_Fetch(wBitStream* _bs);
	WINPR_API void BitStream_Flush(wBitStream* _bs);
	WINPR_API void BitStream_Shift(wBitStream* _bs, UINT32 _nbits);
	WINPR_API void BitStream_Shift32(wBitStream* _bs);
	WINPR_API void BitStream_Write_Bits(wBitStream* _bs, UINT32 _bits, UINT32 _nbits);
	WINPR_API size_t BitStream_GetRemainingLength(wBitStream* _bs);
	WINPR_API size_t BitStream_Capacity(wBitStream* _bs);
	WINPR_API size_t BitStream_Position(wBitStream* _bs);

	WINPR_API UINT32 BitStream_Accumulator(wBitStream* _bs);

	WINPR_API UINT32 BitStream_Mask(wBitStream* _bs);
	WINPR_API void BitStream_SetMask(wBitStream* _bs, UINT32 mask);

	WINPR_API void BitDump(const char* tag, UINT32 level, const BYTE* buffer, UINT32 length,
	                       UINT32 flags);
	WINPR_API UINT32 ReverseBits32(UINT32 bits, UINT32 nbits);

	WINPR_API void BitStream_Attach(wBitStream* bs, BYTE* buffer, UINT32 capacity);

	WINPR_API wBitStream* BitStream_New(void);
	WINPR_API void BitStream_Free(wBitStream* bs);

#ifdef __cplusplus
}
#endif

#endif /* WINPR_UTILS_BITSTREAM_H */
