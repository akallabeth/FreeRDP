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

#include <freerdp/config.h>

#include <string.h>
#include <freerdp/types.h>
#include <freerdp/primitives.h>
#include <freerdp/log.h>

#include "prim_internal.h"
#include <freerdp/codec/color.h>

#define TAG FREERDP_TAG("primitives.copy")

static primitives_t* generic = NULL;

/* ------------------------------------------------------------------------- */
/*static inline BOOL memory_regions_overlap_1d(*/
static BOOL memory_regions_overlap_1d(const BYTE* p1, const BYTE* p2, size_t bytes)
{
	const ULONG_PTR p1m = (const ULONG_PTR)p1;
	const ULONG_PTR p2m = (const ULONG_PTR)p2;

	if (p1m <= p2m)
	{
		if (p1m + bytes > p2m)
			return TRUE;
	}
	else
	{
		if (p2m + bytes > p1m)
			return TRUE;
	}

	/* else */
	return FALSE;
}

/* ------------------------------------------------------------------------- */
/*static inline BOOL memory_regions_overlap_2d( */
static BOOL memory_regions_overlap_2d(const BYTE* p1, int p1Step, int p1Size, const BYTE* p2,
                                      int p2Step, int p2Size, int width, int height)
{
	ULONG_PTR p1m = (ULONG_PTR)p1;
	ULONG_PTR p2m = (ULONG_PTR)p2;

	if (p1m <= p2m)
	{
		ULONG_PTR p1mEnd = p1m + 1ull * (height - 1) * p1Step + 1ull * width * p1Size;

		if (p1mEnd > p2m)
			return TRUE;
	}
	else
	{
		ULONG_PTR p2mEnd = p2m + 1ull * (height - 1) * p2Step + 1ull * width * p2Size;

		if (p2mEnd > p1m)
			return TRUE;
	}

	/* else */
	return FALSE;
}

/* ------------------------------------------------------------------------- */
static pstatus_t general_copy_8u(const BYTE* pSrc, BYTE* pDst, INT32 len)
{
	if (memory_regions_overlap_1d(pSrc, pDst, (size_t)len))
	{
		memmove((void*)pDst, (const void*)pSrc, (size_t)len);
	}
	else
	{
		memcpy((void*)pDst, (const void*)pSrc, (size_t)len);
	}

	return PRIMITIVES_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Copy a block of pixels from one buffer to another.
 * The addresses are assumed to have been already offset to the upper-left
 * corners of the source and destination region of interest.
 */
static pstatus_t general_copy_8u_AC4r(const BYTE* pSrc, INT32 srcStep, BYTE* pDst, INT32 dstStep,
                                      INT32 width, INT32 height)
{
	const BYTE* src = (const BYTE*)pSrc;
	BYTE* dst = (BYTE*)pDst;
	int rowbytes = width * sizeof(UINT32);

	if ((width == 0) || (height == 0))
		return PRIMITIVES_SUCCESS;

	if (memory_regions_overlap_2d(pSrc, srcStep, sizeof(UINT32), pDst, dstStep, sizeof(UINT32),
	                              width, height))
	{
		do
		{
			generic->copy(src, dst, rowbytes);
			src += srcStep;
			dst += dstStep;
		} while (--height);
	}
	else
	{
		/* TODO: do it in one operation when the rowdata is adjacent. */
		do
		{
			/* If we find a replacement for memcpy that is consistently
			 * faster, this could be replaced with that.
			 */
			memcpy(dst, src, rowbytes);
			src += srcStep;
			dst += dstStep;
		} while (--height);
	}

	return PRIMITIVES_SUCCESS;
}

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

	for (SSIZE_T y = 0; y < nHeight; y++)
	{
		const BYTE* WINPR_RESTRICT srcLine =
		    &pSrcData[srcVMultiplier * (y + nYSrc) * nSrcStep + srcVOffset];
		BYTE* WINPR_RESTRICT dstLine =
		    &pDstData[dstVMultiplier * (y + nYDst) * nDstStep + dstVOffset];

		for (SSIZE_T x = 0; x < nWidth; x++)
		{
			dstLine[(x + nXDst) * dstByte + 0] = srcLine[(x + nXSrc) * srcByte + 0];
			dstLine[(x + nXDst) * dstByte + 1] = srcLine[(x + nXSrc) * srcByte + 1];
			dstLine[(x + nXDst) * dstByte + 2] = srcLine[(x + nXSrc) * srcByte + 2];
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

	for (SSIZE_T y = 0; y < nHeight; y++)
	{
		const BYTE* WINPR_RESTRICT srcLine =
		    &pSrcData[srcVMultiplier * (y + nYSrc) * nSrcStep + srcVOffset];
		BYTE* WINPR_RESTRICT dstLine =
		    &pDstData[dstVMultiplier * (y + nYDst) * nDstStep + dstVOffset];

		for (SSIZE_T x = 0; x < nWidth; x++)
		{
			dstLine[(x + nXDst) * dstByte + 0] = srcLine[(x + nXSrc) * srcByte + 0];
			dstLine[(x + nXDst) * dstByte + 1] = srcLine[(x + nXSrc) * srcByte + 1];
			dstLine[(x + nXDst) * dstByte + 2] = srcLine[(x + nXSrc) * srcByte + 2];
		}
	}

	return TRUE;
}

static pstatus_t generic_copy_no_overlap_dst_alpha(
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

/* ------------------------------------------------------------------------- */
void primitives_init_copy(primitives_t* prims)
{
	/* Start with the default. */
	prims->copy_8u = general_copy_8u;
	prims->copy_8u_AC4r = general_copy_8u_AC4r;
	/* This is just an alias with void* parameters */
	prims->copy = (__copy_t)(prims->copy_8u);
	prims->copy_no_overlap_dst_alpha = generic_copy_no_overlap_dst_alpha;
}

#if defined(WITH_SSE2) || defined(WITH_NEON)
extern void primitives_init_copy_sse(primitives_t* prims);

void primitives_init_copy_opt(primitives_t* prims)
{
	generic = primitives_get_generic();
	primitives_init_copy(prims);
	/* Pick tuned versions if possible. */
	/* Performance with an SSE2 version with no prefetch seemed to be
	 * all over the map vs. memcpy.
	 * Sometimes it was significantly faster, sometimes dreadfully slower,
	 * and it seemed to vary a lot depending on block size and processor.
	 * Hence, no SSE version is used here unless once can be written that
	 * is consistently faster than memcpy.
	 */
	/* This is just an alias with void* parameters */
	prims->copy = (__copy_t)(prims->copy_8u);
	primitives_init_copy_sse(prims);
}
#endif
