/* FreeRDP: A Remote Desktop Protocol Client
 * Copy operations.
 * vi:ts=4 sw=4:
 *
 * (c) Copyright 2012 Hewlett-Packard Development Company, L.P.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <winpr/sysinfo.h>

#include <freerdp/config.h>

#include <string.h>
#include <freerdp/types.h>
#include <freerdp/primitives.h>
#include <freerdp/log.h>

#include "prim_internal.h"
#include <freerdp/codec/color.h>

#define TAG FREERDP_TAG("primitives.copy")

#if defined(WITH_SSE2)
#include <emmintrin.h>
#include <immintrin.h>

static INLINE BOOL freerdp_image_copy_bgr24_bgrx32(BYTE* WINPR_RESTRICT pDstData, UINT32 nDstStep,
                                                   UINT32 nXDst, UINT32 nYDst, UINT32 nWidth,
                                                   UINT32 nHeight,
                                                   const BYTE* WINPR_RESTRICT pSrcData,
                                                   UINT32 nSrcStep, UINT32 nXSrc, UINT32 nYSrc,
                                                   SSIZE_T srcVMultiplier, SSIZE_T srcVOffset,
                                                   SSIZE_T dstVMultiplier, SSIZE_T dstVOffset)
{

	const SSIZE_T srcByte = 3;
	const SSIZE_T dstByte = 4;

	const __m128i mask = _mm_set_epi32(0xFFFFFF00, 0xFFFFFF00, 0xFFFFFF00, 0xFFFFFF00);
	for (SSIZE_T y = 0; y < nHeight; y++)
	{
		const BYTE* WINPR_RESTRICT srcLine =
		    &pSrcData[srcVMultiplier * (y + nYSrc) * nSrcStep + srcVOffset];
		BYTE* WINPR_RESTRICT dstLine =
		    &pDstData[dstVMultiplier * (y + nYDst) * nDstStep + dstVOffset];

		for (SSIZE_T x = 0; x < nWidth; x += 4)
		{
			const __m128i* src = (const __m128i*)&srcLine[(x + nXSrc) * srcByte];
			__m128i* dst = (__m128i*)&dstLine[(x + nXDst) * dstByte];
			const __m128i s0 = _mm_loadu_si128(src);
			const __m128i s1 = _mm_loadu_si128(dst);
			const __m128i s2 = _mm_shuffle_epi8(s1, mask);
			__m128i d0 = _mm_blendv_epi8(s0, s2, mask);
			_mm_storeu_si128(dst, d0);
		}
	}

	return TRUE;
}

static INLINE BOOL freerdp_image_copy_bgrx32_bgrx32(BYTE* WINPR_RESTRICT pDstData, UINT32 nDstStep,
                                                    UINT32 nXDst, UINT32 nYDst, UINT32 nWidth,
                                                    UINT32 nHeight,
                                                    const BYTE* WINPR_RESTRICT pSrcData,
                                                    UINT32 nSrcStep, UINT32 nXSrc, UINT32 nYSrc,
                                                    SSIZE_T srcVMultiplier, SSIZE_T srcVOffset,
                                                    SSIZE_T dstVMultiplier, SSIZE_T dstVOffset)
{

	const SSIZE_T srcByte = 4;
	const SSIZE_T dstByte = 4;

	const __m128i mask = _mm_set_epi32(0xFFFFFF00, 0xFFFFFF00, 0xFFFFFF00, 0xFFFFFF00);
	for (SSIZE_T y = 0; y < nHeight; y++)
	{
		const BYTE* WINPR_RESTRICT srcLine =
		    &pSrcData[srcVMultiplier * (y + nYSrc) * nSrcStep + srcVOffset];
		BYTE* WINPR_RESTRICT dstLine =
		    &pDstData[dstVMultiplier * (y + nYDst) * nDstStep + dstVOffset];

		for (SSIZE_T x = 0; x < nWidth; x += 4)
		{
			const __m128i* src = (const __m128i*)&srcLine[(x + nXSrc) * srcByte];
			__m128i* dst = (__m128i*)&dstLine[(x + nXDst) * dstByte];
			const __m128i s0 = _mm_loadu_si128(src);
			const __m128i s1 = _mm_loadu_si128(dst);
			__m128i d0 = _mm_blendv_epi8(s1, s0, mask);
			_mm_storeu_si128(dst, d0);
		}
	}

	return TRUE;
}

static pstatus_t sse_copy_no_overlap_dst_alpha(
    BYTE* WINPR_RESTRICT pDstData, DWORD DstFormat, UINT32 nDstStep, UINT32 nXDst, UINT32 nYDst,
    UINT32 nWidth, UINT32 nHeight, const BYTE* WINPR_RESTRICT pSrcData, DWORD SrcFormat,
    UINT32 nSrcStep, UINT32 nXSrc, UINT32 nYSrc, const gdiPalette* WINPR_RESTRICT palette,
    SSIZE_T srcVMultiplier, SSIZE_T srcVOffset, SSIZE_T dstVMultiplier, SSIZE_T dstVOffset)
{
	WINPR_ASSERT(pDstData);
	WINPR_ASSERT(pSrcData);

	switch (SrcFormat)
	{
		case PIXEL_FORMAT_BGR24:
			switch (DstFormat)
			{
				case PIXEL_FORMAT_BGRX32:
				case PIXEL_FORMAT_BGRA32:
					return freerdp_image_copy_bgr24_bgrx32(
					    pDstData, nDstStep, nXDst, nYDst, nWidth, nHeight, pSrcData, nSrcStep,
					    nXSrc, nYSrc, srcVMultiplier, srcVOffset, dstVMultiplier, dstVOffset);
				default:
					break;
			}
			break;
		case PIXEL_FORMAT_BGRX32:
		case PIXEL_FORMAT_BGRA32:
			switch (DstFormat)
			{
				case PIXEL_FORMAT_BGRX32:
				case PIXEL_FORMAT_BGRA32:
					return freerdp_image_copy_bgrx32_bgrx32(
					    pDstData, nDstStep, nXDst, nYDst, nWidth, nHeight, pSrcData, nSrcStep,
					    nXSrc, nYSrc, srcVMultiplier, srcVOffset, dstVMultiplier, dstVOffset);
				default:
					break;
			}
			break;
		default:
			break;
	}

	WLog_DBG(TAG, "unsupported format src %s --> dst %s", FreeRDPGetColorFormatName(SrcFormat),
	         FreeRDPGetColorFormatName(DstFormat));
	return -1;
}
#endif

/* ------------------------------------------------------------------------- */
void primitives_init_copy_sse(primitives_t* prims)
{
#if defined(WITH_SSE2)
	if (IsProcessorFeaturePresent(PF_SSE4_1_INSTRUCTIONS_AVAILABLE))
	{
		prims->copy_no_overlap_dst_alpha = sse_copy_no_overlap_dst_alpha;
	}
#else
	WINPR_UNUSED(prims);
#endif
}
