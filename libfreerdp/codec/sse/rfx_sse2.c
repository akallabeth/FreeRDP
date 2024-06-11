/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RemoteFX Codec Library - SSE2 Optimizations
 *
 * Copyright 2011 Stephen Erisman
 * Copyright 2011 Norbert Federa <norbert.federa@thincast.com>
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
#include <freerdp/log.h>

#include "../rfx_types.h"
#include "rfx_sse2.h"

#define TAG FREERDP_TAG("codec.rfx.sse2")

#if defined(WITH_SSE2)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winpr/sysinfo.h>

#include <xmmintrin.h>
#include <emmintrin.h>

#ifdef _MSC_VER
#define __attribute__(...)
#endif

#define CACHE_LINE_BYTES 64

#ifndef __clang__
#define ATTRIBUTES __gnu_inline__, __always_inline__, __artificial__
#else
#define ATTRIBUTES __gnu_inline__, __always_inline__
#endif

#define _mm_between_epi16(_val, _min, _max)                    \
	do                                                         \
	{                                                          \
		_val = _mm_min_epi16(_max, _mm_max_epi16(_val, _min)); \
	} while (0)

static __inline void __attribute__((ATTRIBUTES))
_mm_prefetch_buffer(char* WINPR_RESTRICT buffer, int num_bytes)
{
	__m128i* buf = (__m128i*)buffer;

	for (unsigned int i = 0; i < (num_bytes / sizeof(__m128i));
	     i += (CACHE_LINE_BYTES / sizeof(__m128i)))
	{
		_mm_prefetch((char*)(&buf[i]), _MM_HINT_NTA);
	}
}

/* rfx_decode_ycbcr_to_rgb_sse2 code now resides in the primitives library. */
/* rfx_encode_rgb_to_ycbcr_sse2 code now resides in the primitives library. */

static __inline void __attribute__((ATTRIBUTES))
rfx_quantization_decode_block_sse2(INT16* WINPR_RESTRICT buffer, const size_t buffer_size,
                                   const UINT32 factor)
{
	__m128i a;
	__m128i* ptr = (__m128i*)buffer;
	__m128i* buf_end = (__m128i*)(buffer + buffer_size);

	if (factor == 0)
		return;

	do
	{
		a = _mm_load_si128(ptr);
		a = _mm_slli_epi16(a, factor);
		_mm_store_si128(ptr, a);
		ptr++;
	} while (ptr < buf_end);
}

static void rfx_quantization_decode_sse2(INT16* WINPR_RESTRICT buffer,
                                         const UINT32* WINPR_RESTRICT quantVals)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(quantVals);

	_mm_prefetch_buffer((char*)buffer, 4096 * sizeof(INT16));
	rfx_quantization_decode_block_sse2(&buffer[0], 1024, quantVals[8] - 1);    /* HL1 */
	rfx_quantization_decode_block_sse2(&buffer[1024], 1024, quantVals[7] - 1); /* LH1 */
	rfx_quantization_decode_block_sse2(&buffer[2048], 1024, quantVals[9] - 1); /* HH1 */
	rfx_quantization_decode_block_sse2(&buffer[3072], 256, quantVals[5] - 1);  /* HL2 */
	rfx_quantization_decode_block_sse2(&buffer[3328], 256, quantVals[4] - 1);  /* LH2 */
	rfx_quantization_decode_block_sse2(&buffer[3584], 256, quantVals[6] - 1);  /* HH2 */
	rfx_quantization_decode_block_sse2(&buffer[3840], 64, quantVals[2] - 1);   /* HL3 */
	rfx_quantization_decode_block_sse2(&buffer[3904], 64, quantVals[1] - 1);   /* LH3 */
	rfx_quantization_decode_block_sse2(&buffer[3968], 64, quantVals[3] - 1);   /* HH3 */
	rfx_quantization_decode_block_sse2(&buffer[4032], 64, quantVals[0] - 1);   /* LL3 */
}

static __inline void __attribute__((ATTRIBUTES))
rfx_quantization_encode_block_sse2(INT16* WINPR_RESTRICT buffer, const int buffer_size,
                                   const UINT32 factor)
{
	__m128i a;
	__m128i* ptr = (__m128i*)buffer;
	__m128i* buf_end = (__m128i*)(buffer + buffer_size);
	__m128i half;

	if (factor == 0)
		return;

	half = _mm_set1_epi16(1 << (factor - 1));

	do
	{
		a = _mm_load_si128(ptr);
		a = _mm_add_epi16(a, half);
		a = _mm_srai_epi16(a, factor);
		_mm_store_si128(ptr, a);
		ptr++;
	} while (ptr < buf_end);
}

static void rfx_quantization_encode_sse2(INT16* WINPR_RESTRICT buffer,
                                         const UINT32* WINPR_RESTRICT quantization_values)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(quantization_values);

	_mm_prefetch_buffer((char*)buffer, 4096 * sizeof(INT16));
	rfx_quantization_encode_block_sse2(buffer, 1024, quantization_values[8] - 6);        /* HL1 */
	rfx_quantization_encode_block_sse2(buffer + 1024, 1024, quantization_values[7] - 6); /* LH1 */
	rfx_quantization_encode_block_sse2(buffer + 2048, 1024, quantization_values[9] - 6); /* HH1 */
	rfx_quantization_encode_block_sse2(buffer + 3072, 256, quantization_values[5] - 6);  /* HL2 */
	rfx_quantization_encode_block_sse2(buffer + 3328, 256, quantization_values[4] - 6);  /* LH2 */
	rfx_quantization_encode_block_sse2(buffer + 3584, 256, quantization_values[6] - 6);  /* HH2 */
	rfx_quantization_encode_block_sse2(buffer + 3840, 64, quantization_values[2] - 6);   /* HL3 */
	rfx_quantization_encode_block_sse2(buffer + 3904, 64, quantization_values[1] - 6);   /* LH3 */
	rfx_quantization_encode_block_sse2(buffer + 3968, 64, quantization_values[3] - 6);   /* HH3 */
	rfx_quantization_encode_block_sse2(buffer + 4032, 64, quantization_values[0] - 6);   /* LL3 */
	rfx_quantization_encode_block_sse2(buffer, 4096, 5);
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_decode_block_horiz_sse2(INT16* WINPR_RESTRICT l, INT16* WINPR_RESTRICT h,
                                   INT16* WINPR_RESTRICT dst, int subband_width)
{
	INT16* l_ptr = l;
	INT16* h_ptr = h;
	INT16* dst_ptr = dst;
	int first = 0;
	int last = 0;
	__m128i l_n;
	__m128i h_n;
	__m128i h_n_m;
	__m128i tmp_n;
	__m128i dst_n;
	__m128i dst_n_p;
	__m128i dst1;
	__m128i dst2;

	for (int y = 0; y < subband_width; y++)
	{
		/* Even coefficients */
		for (int n = 0; n < subband_width; n += 8)
		{
			/* dst[2n] = l[n] - ((h[n-1] + h[n] + 1) >> 1); */
			l_n = _mm_load_si128((__m128i*)l_ptr);
			h_n = _mm_load_si128((__m128i*)h_ptr);
			h_n_m = _mm_loadu_si128((__m128i*)(h_ptr - 1));

			if (n == 0)
			{
				first = _mm_extract_epi16(h_n_m, 1);
				h_n_m = _mm_insert_epi16(h_n_m, first, 0);
			}

			tmp_n = _mm_add_epi16(h_n, h_n_m);
			tmp_n = _mm_add_epi16(tmp_n, _mm_set1_epi16(1));
			tmp_n = _mm_srai_epi16(tmp_n, 1);
			dst_n = _mm_sub_epi16(l_n, tmp_n);
			_mm_store_si128((__m128i*)l_ptr, dst_n);
			l_ptr += 8;
			h_ptr += 8;
		}

		l_ptr -= subband_width;
		h_ptr -= subband_width;

		/* Odd coefficients */
		for (int n = 0; n < subband_width; n += 8)
		{
			/* dst[2n + 1] = (h[n] << 1) + ((dst[2n] + dst[2n + 2]) >> 1); */
			h_n = _mm_load_si128((__m128i*)h_ptr);
			h_n = _mm_slli_epi16(h_n, 1);
			dst_n = _mm_load_si128((__m128i*)(l_ptr));
			dst_n_p = _mm_loadu_si128((__m128i*)(l_ptr + 1));

			if (n == subband_width - 8)
			{
				last = _mm_extract_epi16(dst_n_p, 6);
				dst_n_p = _mm_insert_epi16(dst_n_p, last, 7);
			}

			tmp_n = _mm_add_epi16(dst_n_p, dst_n);
			tmp_n = _mm_srai_epi16(tmp_n, 1);
			tmp_n = _mm_add_epi16(tmp_n, h_n);
			dst1 = _mm_unpacklo_epi16(dst_n, tmp_n);
			dst2 = _mm_unpackhi_epi16(dst_n, tmp_n);
			_mm_store_si128((__m128i*)dst_ptr, dst1);
			_mm_store_si128((__m128i*)(dst_ptr + 8), dst2);
			l_ptr += 8;
			h_ptr += 8;
			dst_ptr += 16;
		}
	}
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_decode_block_vert_sse2(INT16* WINPR_RESTRICT l, INT16* WINPR_RESTRICT h,
                                  INT16* WINPR_RESTRICT dst, int subband_width)
{
	INT16* l_ptr = l;
	INT16* h_ptr = h;
	INT16* dst_ptr = dst;
	__m128i l_n;
	__m128i h_n;
	__m128i tmp_n;
	__m128i h_n_m;
	__m128i dst_n;
	__m128i dst_n_m;
	__m128i dst_n_p;
	int total_width = subband_width + subband_width;

	/* Even coefficients */
	for (int n = 0; n < subband_width; n++)
	{
		for (int x = 0; x < total_width; x += 8)
		{
			/* dst[2n] = l[n] - ((h[n-1] + h[n] + 1) >> 1); */
			l_n = _mm_load_si128((__m128i*)l_ptr);
			h_n = _mm_load_si128((__m128i*)h_ptr);
			tmp_n = _mm_add_epi16(h_n, _mm_set1_epi16(1));

			if (n == 0)
				tmp_n = _mm_add_epi16(tmp_n, h_n);
			else
			{
				h_n_m = _mm_loadu_si128((__m128i*)(h_ptr - total_width));
				tmp_n = _mm_add_epi16(tmp_n, h_n_m);
			}

			tmp_n = _mm_srai_epi16(tmp_n, 1);
			dst_n = _mm_sub_epi16(l_n, tmp_n);
			_mm_store_si128((__m128i*)dst_ptr, dst_n);
			l_ptr += 8;
			h_ptr += 8;
			dst_ptr += 8;
		}

		dst_ptr += total_width;
	}

	h_ptr = h;
	dst_ptr = dst + total_width;

	/* Odd coefficients */
	for (int n = 0; n < subband_width; n++)
	{
		for (int x = 0; x < total_width; x += 8)
		{
			/* dst[2n + 1] = (h[n] << 1) + ((dst[2n] + dst[2n + 2]) >> 1); */
			h_n = _mm_load_si128((__m128i*)h_ptr);
			dst_n_m = _mm_load_si128((__m128i*)(dst_ptr - total_width));
			h_n = _mm_slli_epi16(h_n, 1);
			tmp_n = dst_n_m;

			if (n == subband_width - 1)
				tmp_n = _mm_add_epi16(tmp_n, dst_n_m);
			else
			{
				dst_n_p = _mm_loadu_si128((__m128i*)(dst_ptr + total_width));
				tmp_n = _mm_add_epi16(tmp_n, dst_n_p);
			}

			tmp_n = _mm_srai_epi16(tmp_n, 1);
			dst_n = _mm_add_epi16(tmp_n, h_n);
			_mm_store_si128((__m128i*)dst_ptr, dst_n);
			h_ptr += 8;
			dst_ptr += 8;
		}

		dst_ptr += total_width;
	}
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_decode_block_sse2(INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT idwt,
                             int subband_width)
{
	INT16* hl = NULL;
	INT16* lh = NULL;
	INT16* hh = NULL;
	INT16* ll = NULL;
	INT16* l_dst = NULL;
	INT16* h_dst = NULL;
	_mm_prefetch_buffer((char*)idwt, subband_width * 4 * sizeof(INT16));
	/* Inverse DWT in horizontal direction, results in 2 sub-bands in L, H order in tmp buffer idwt.
	 */
	/* The 4 sub-bands are stored in HL(0), LH(1), HH(2), LL(3) order. */
	/* The lower part L uses LL(3) and HL(0). */
	/* The higher part H uses LH(1) and HH(2). */
	ll = buffer + subband_width * subband_width * 3;
	hl = buffer;
	l_dst = idwt;
	rfx_dwt_2d_decode_block_horiz_sse2(ll, hl, l_dst, subband_width);
	lh = buffer + subband_width * subband_width;
	hh = buffer + subband_width * subband_width * 2;
	h_dst = idwt + subband_width * subband_width * 2;
	rfx_dwt_2d_decode_block_horiz_sse2(lh, hh, h_dst, subband_width);
	/* Inverse DWT in vertical direction, results are stored in original buffer. */
	rfx_dwt_2d_decode_block_vert_sse2(l_dst, h_dst, buffer, subband_width);
}

static void rfx_dwt_2d_decode_sse2(INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT dwt_buffer)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(dwt_buffer);

	_mm_prefetch_buffer((char*)buffer, 4096 * sizeof(INT16));
	rfx_dwt_2d_decode_block_sse2(&buffer[3840], dwt_buffer, 8);
	rfx_dwt_2d_decode_block_sse2(&buffer[3072], dwt_buffer, 16);
	rfx_dwt_2d_decode_block_sse2(&buffer[0], dwt_buffer, 32);
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_encode_block_vert_sse2(INT16* WINPR_RESTRICT src, INT16* WINPR_RESTRICT l,
                                  INT16* WINPR_RESTRICT h, int subband_width)
{
	int total_width = 0;
	__m128i src_2n;
	__m128i src_2n_1;
	__m128i src_2n_2;
	__m128i h_n;
	__m128i h_n_m;
	__m128i l_n;
	total_width = subband_width << 1;

	for (int n = 0; n < subband_width; n++)
	{
		for (int x = 0; x < total_width; x += 8)
		{
			src_2n = _mm_load_si128((__m128i*)src);
			src_2n_1 = _mm_load_si128((__m128i*)(src + total_width));

			if (n < subband_width - 1)
				src_2n_2 = _mm_load_si128((__m128i*)(src + 2 * total_width));
			else
				src_2n_2 = src_2n;

			/* h[n] = (src[2n + 1] - ((src[2n] + src[2n + 2]) >> 1)) >> 1 */
			h_n = _mm_add_epi16(src_2n, src_2n_2);
			h_n = _mm_srai_epi16(h_n, 1);
			h_n = _mm_sub_epi16(src_2n_1, h_n);
			h_n = _mm_srai_epi16(h_n, 1);
			_mm_store_si128((__m128i*)h, h_n);

			if (n == 0)
				h_n_m = h_n;
			else
				h_n_m = _mm_load_si128((__m128i*)(h - total_width));

			/* l[n] = src[2n] + ((h[n - 1] + h[n]) >> 1) */
			l_n = _mm_add_epi16(h_n_m, h_n);
			l_n = _mm_srai_epi16(l_n, 1);
			l_n = _mm_add_epi16(l_n, src_2n);
			_mm_store_si128((__m128i*)l, l_n);
			src += 8;
			l += 8;
			h += 8;
		}

		src += total_width;
	}
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_encode_block_horiz_sse2(INT16* WINPR_RESTRICT src, INT16* WINPR_RESTRICT l,
                                   INT16* WINPR_RESTRICT h, int subband_width)
{
	int first = 0;
	__m128i src_2n;
	__m128i src_2n_1;
	__m128i src_2n_2;
	__m128i h_n;
	__m128i h_n_m;
	__m128i l_n;

	for (int y = 0; y < subband_width; y++)
	{
		for (int n = 0; n < subband_width; n += 8)
		{
			/* The following 3 Set operations consumes more than half of the total DWT processing
			 * time! */
			src_2n =
			    _mm_set_epi16(src[14], src[12], src[10], src[8], src[6], src[4], src[2], src[0]);
			src_2n_1 =
			    _mm_set_epi16(src[15], src[13], src[11], src[9], src[7], src[5], src[3], src[1]);
			src_2n_2 = _mm_set_epi16(n == subband_width - 8 ? src[14] : src[16], src[14], src[12],
			                         src[10], src[8], src[6], src[4], src[2]);
			/* h[n] = (src[2n + 1] - ((src[2n] + src[2n + 2]) >> 1)) >> 1 */
			h_n = _mm_add_epi16(src_2n, src_2n_2);
			h_n = _mm_srai_epi16(h_n, 1);
			h_n = _mm_sub_epi16(src_2n_1, h_n);
			h_n = _mm_srai_epi16(h_n, 1);
			_mm_store_si128((__m128i*)h, h_n);
			h_n_m = _mm_loadu_si128((__m128i*)(h - 1));

			if (n == 0)
			{
				first = _mm_extract_epi16(h_n_m, 1);
				h_n_m = _mm_insert_epi16(h_n_m, first, 0);
			}

			/* l[n] = src[2n] + ((h[n - 1] + h[n]) >> 1) */
			l_n = _mm_add_epi16(h_n_m, h_n);
			l_n = _mm_srai_epi16(l_n, 1);
			l_n = _mm_add_epi16(l_n, src_2n);
			_mm_store_si128((__m128i*)l, l_n);
			src += 16;
			l += 8;
			h += 8;
		}
	}
}

static __inline void __attribute__((ATTRIBUTES))
rfx_dwt_2d_encode_block_sse2(INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT dwt,
                             int subband_width)
{
	INT16* hl = NULL;
	INT16* lh = NULL;
	INT16* hh = NULL;
	INT16* ll = NULL;
	INT16* l_src = NULL;
	INT16* h_src = NULL;
	_mm_prefetch_buffer((char*)dwt, subband_width * 4 * sizeof(INT16));
	/* DWT in vertical direction, results in 2 sub-bands in L, H order in tmp buffer dwt. */
	l_src = dwt;
	h_src = dwt + subband_width * subband_width * 2;
	rfx_dwt_2d_encode_block_vert_sse2(buffer, l_src, h_src, subband_width);
	/* DWT in horizontal direction, results in 4 sub-bands in HL(0), LH(1), HH(2), LL(3) order,
	 * stored in original buffer. */
	/* The lower part L generates LL(3) and HL(0). */
	/* The higher part H generates LH(1) and HH(2). */
	ll = buffer + subband_width * subband_width * 3;
	hl = buffer;
	lh = buffer + subband_width * subband_width;
	hh = buffer + subband_width * subband_width * 2;
	rfx_dwt_2d_encode_block_horiz_sse2(l_src, ll, hl, subband_width);
	rfx_dwt_2d_encode_block_horiz_sse2(h_src, lh, hh, subband_width);
}

static void rfx_dwt_2d_encode_sse2(INT16* WINPR_RESTRICT buffer, INT16* WINPR_RESTRICT dwt_buffer)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(dwt_buffer);

	_mm_prefetch_buffer((char*)buffer, 4096 * sizeof(INT16));
	rfx_dwt_2d_encode_block_sse2(buffer, dwt_buffer, 32);
	rfx_dwt_2d_encode_block_sse2(buffer + 3072, dwt_buffer, 16);
	rfx_dwt_2d_encode_block_sse2(buffer + 3840, dwt_buffer, 8);
}

/*
 * Band	    Offset      Dimensions  Size
 *
 * HL1      0           31x33       1023
 * LH1      1023        33x31       1023
 * HH1      2046        31x31       961
 *
 * HL2      3007        16x17       272
 * LH2      3279        17x16       272
 * HH2      3551        16x16       256
 *
 * HL3      3807        8x9         72
 * LH3      3879        9x8         72
 * HH3      3951        8x8         64
 *
 * LL3      4015        9x9         81
 */

static INLINE void sse_progressive_rfx_idwt_x(const INT16* WINPR_RESTRICT pLowBand, size_t nLowStep,
                                              const INT16* WINPR_RESTRICT pHighBand,
                                              size_t nHighStep, INT16* WINPR_RESTRICT pDstBand,
                                              size_t nDstStep, size_t nLowCount, size_t nHighCount,
                                              size_t nDstCount)
{
	INT16 L0 = 0;
	INT16 H0 = 0;
	INT16 H1 = 0;
	INT16 X0 = 0;
	INT16 X1 = 0;
	INT16 X2 = 0;

	for (size_t i = 0; i < nDstCount; i++)
	{
		const INT16* pL = pLowBand;
		const INT16* pH = pHighBand;
		INT16* pX = pDstBand;
		H0 = *pH++;
		L0 = *pL++;
		X0 = L0 - H0;
		X2 = L0 - H0;

		WINPR_PRAGMA_UNROLL_LOOP
		for (size_t j = 0; j < (nHighCount - 1); j++)
		{
			H1 = *pH;
			pH++;
			L0 = *pL;
			pL++;
			X2 = L0 - ((H0 + H1) / 2);
			X1 = ((X0 + X2) / 2) + (2 * H0);
			pX[0] = X0;
			pX[1] = X1;
			pX += 2;
			X0 = X2;
			H0 = H1;
		}

		if (nLowCount <= (nHighCount + 1))
		{
			if (nLowCount <= nHighCount)
			{
				pX[0] = X2;
				pX[1] = X2 + (2 * H0);
			}
			else
			{
				L0 = *pL;
				pL++;
				X0 = L0 - H0;
				pX[0] = X2;
				pX[1] = ((X0 + X2) / 2) + (2 * H0);
				pX[2] = X0;
			}
		}
		else
		{
			L0 = *pL;
			pL++;
			X0 = L0 - (H0 / 2);
			pX[0] = X2;
			pX[1] = ((X0 + X2) / 2) + (2 * H0);
			pX[2] = X0;
			L0 = *pL;
			pL++;
			pX[3] = (X0 + L0) / 2;
		}

		pLowBand += nLowStep;
		pHighBand += nHighStep;
		pDstBand += nDstStep;
	}
}

static INLINE void sse_progressive_rfx_idwt_y(const INT16* WINPR_RESTRICT pLowBand, size_t nLowStep,
                                              const INT16* WINPR_RESTRICT pHighBand,
                                              size_t nHighStep, INT16* WINPR_RESTRICT pDstBand,
                                              size_t nDstStep, size_t nLowCount, size_t nHighCount,
                                              size_t nDstCount)
{
	INT16 L0 = 0;
	INT16 H0 = 0;
	INT16 H1 = 0;
	INT16 X0 = 0;
	INT16 X1 = 0;
	INT16 X2 = 0;

	for (size_t i = 0; i < nDstCount; i++)
	{
		const INT16* pL = pLowBand;
		const INT16* pH = pHighBand;
		INT16* pX = pDstBand;
		H0 = *pH;
		pH += nHighStep;
		L0 = *pL;
		pL += nLowStep;
		X0 = L0 - H0;
		X2 = L0 - H0;

		WINPR_PRAGMA_UNROLL_LOOP
		for (size_t j = 0; j < (nHighCount - 1); j++)
		{
			H1 = *pH;
			pH += nHighStep;
			L0 = *pL;
			pL += nLowStep;
			X2 = L0 - ((H0 + H1) / 2);
			X1 = ((X0 + X2) / 2) + (2 * H0);
			*pX = X0;
			pX += nDstStep;
			*pX = X1;
			pX += nDstStep;
			X0 = X2;
			H0 = H1;
		}

		if (nLowCount <= (nHighCount + 1))
		{
			if (nLowCount <= nHighCount)
			{
				*pX = X2;
				pX += nDstStep;
				*pX = X2 + (2 * H0);
			}
			else
			{
				L0 = *pL;
				X0 = L0 - H0;
				*pX = X2;
				pX += nDstStep;
				*pX = ((X0 + X2) / 2) + (2 * H0);
				pX += nDstStep;
				*pX = X0;
			}
		}
		else
		{
			L0 = *pL;
			pL += nLowStep;
			X0 = L0 - (H0 / 2);
			*pX = X2;
			pX += nDstStep;
			*pX = ((X0 + X2) / 2) + (2 * H0);
			pX += nDstStep;
			*pX = X0;
			pX += nDstStep;
			L0 = *pL;
			*pX = (X0 + L0) / 2;
		}

		pLowBand++;
		pHighBand++;
		pDstBand++;
	}
}

static INLINE size_t sse_progressive_rfx_get_band_l_count(size_t level)
{
	return (64 >> level) + 1;
}

static INLINE size_t sse_progressive_rfx_get_band_h_count(size_t level)
{
	if (level == 1)
		return (64 >> 1) - 1;
	else
		return (64 + (1 << (level - 1))) >> level;
}

static INLINE void sse_progressive_rfx_dwt_2d_decode_block(INT16* WINPR_RESTRICT buffer,
                                                           INT16* WINPR_RESTRICT temp, size_t level)
{
	size_t nDstStepX = 0;
	size_t nDstStepY = 0;
	const INT16* WINPR_RESTRICT HL = NULL;
	const INT16* WINPR_RESTRICT LH = NULL;
	const INT16* WINPR_RESTRICT HH = NULL;
	INT16* WINPR_RESTRICT LL = NULL;
	INT16* WINPR_RESTRICT L = NULL;
	INT16* WINPR_RESTRICT H = NULL;
	INT16* WINPR_RESTRICT LLx = NULL;

	const size_t nBandL = sse_progressive_rfx_get_band_l_count(level);
	const size_t nBandH = sse_progressive_rfx_get_band_h_count(level);
	size_t offset = 0;

	HL = &buffer[offset];
	offset += (nBandH * nBandL);
	LH = &buffer[offset];
	offset += (nBandL * nBandH);
	HH = &buffer[offset];
	offset += (nBandH * nBandH);
	LL = &buffer[offset];
	nDstStepX = (nBandL + nBandH);
	nDstStepY = (nBandL + nBandH);
	offset = 0;
	L = &temp[offset];
	offset += (nBandL * nDstStepX);
	H = &temp[offset];
	LLx = &buffer[0];

	/* horizontal (LL + HL -> L) */
	sse_progressive_rfx_idwt_x(LL, nBandL, HL, nBandH, L, nDstStepX, nBandL, nBandH, nBandL);

	/* horizontal (LH + HH -> H) */
	sse_progressive_rfx_idwt_x(LH, nBandL, HH, nBandH, H, nDstStepX, nBandL, nBandH, nBandH);

	/* vertical (L + H -> LL) */
	sse_progressive_rfx_idwt_y(L, nDstStepX, H, nDstStepX, LLx, nDstStepY, nBandL, nBandH,
	                           nBandL + nBandH);
}

static void sse_rfx_dwt_2d_extrapolate_decode(INT16* WINPR_RESTRICT buffer,
                                              INT16* WINPR_RESTRICT temp)
{
	WINPR_ASSERT(buffer);
	WINPR_ASSERT(temp);
	sse_progressive_rfx_dwt_2d_decode_block(&buffer[3807], temp, 3);
	sse_progressive_rfx_dwt_2d_decode_block(&buffer[3007], temp, 2);
	sse_progressive_rfx_dwt_2d_decode_block(&buffer[0], temp, 1);
}
#endif

void rfx_init_sse2(RFX_CONTEXT* context)
{
#if defined(WITH_SSE2)
	if (!IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE))
		return;

	PROFILER_RENAME(context->priv->prof_rfx_quantization_decode, "rfx_quantization_decode_sse2")
	PROFILER_RENAME(context->priv->prof_rfx_quantization_encode, "rfx_quantization_encode_sse2")
	PROFILER_RENAME(context->priv->prof_rfx_dwt_2d_decode, "rfx_dwt_2d_decode_sse2")
	PROFILER_RENAME(context->priv->prof_rfx_dwt_2d_encode, "rfx_dwt_2d_encode_sse2")
	context->quantization_decode = rfx_quantization_decode_sse2;
	context->quantization_encode = rfx_quantization_encode_sse2;
	context->dwt_2d_decode = rfx_dwt_2d_decode_sse2;
	context->dwt_2d_encode = rfx_dwt_2d_encode_sse2;
	context->dwt_2d_extrapolate_decode = sse_rfx_dwt_2d_extrapolate_decode;
#else
	WINPR_UNUSED(context);
#endif
}
