
#include <math.h>

#include <winpr/crt.h>
#include <winpr/print.h>

#include <freerdp/freerdp.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/bitmap.h>
#include <freerdp/codec/interleaved.h>
#include <winpr/crypto.h>

static BOOL run_encode_decode(UINT16 bpp, BITMAP_INTERLEAVED_CONTEXT* encoder,
                              BITMAP_INTERLEAVED_CONTEXT* decoder)
{
	BOOL rc = FALSE;
	UINT32 i, j;
	const UINT32 w = 64;
	const UINT32 h = 64;
	const UINT32 x = 0;
	const UINT32 y = 0;
	const UINT32 format = PIXEL_FORMAT_RGBX32;
	const UINT32 bstep = GetBytesPerPixel(format);
	const size_t step = (w + 13) * 4;
	const size_t SrcSize = step * h;
	const float maxDiff = 4.0f;
	UINT32 DstSize = SrcSize;
	BYTE* pSrcData = malloc(SrcSize);
	BYTE* pDstData = malloc(SrcSize);
	BYTE* tmp = malloc(SrcSize);

	if (!pSrcData || !pDstData || !tmp)
		goto fail;

	winpr_RAND(pSrcData, SrcSize);

	if (!bitmap_interleaved_context_reset(encoder) || !bitmap_interleaved_context_reset(decoder))
		goto fail;

	if (!interleaved_compress(decoder, tmp, &DstSize, w, h, pSrcData,
	                          format, step, x, y, NULL, bpp))
		goto fail;

	if (!interleaved_decompress(encoder, tmp, DstSize, w, h, bpp, pDstData,
	                            format, step, x, y, w, h, NULL))
		goto fail;

	for (i = 0; i < h; i++)
	{
		const BYTE* srcLine = &pSrcData[i * step];
		const BYTE* dstLine = &pDstData[i * step];

		for (j = 0; j < w; j++)
		{
			BYTE r, g, b, dr, dg, db;
			const UINT32 srcColor = ReadColor(&srcLine[j * bstep], format);
			const UINT32 dstColor = ReadColor(&dstLine[j * bstep], format);
			SplitColor(srcColor, format, &r, &g, &b, NULL, NULL);
			SplitColor(dstColor, format, &dr, &dg, &db, NULL, NULL);

			if (fabsf((float)r - dr) > maxDiff)
				goto fail;

			if (fabsf((float)g - dg) > maxDiff)
				goto fail;

			if (fabsf((float)b - db) > maxDiff)
				goto fail;
			}
	}

	rc = TRUE;
fail:
	free(pSrcData);
	free(pDstData);
	free(tmp);
	return rc;
}

int TestFreeRDPCodecInterleaved(int argc, char* argv[])
{
	BITMAP_INTERLEAVED_CONTEXT* encoder, * decoder;
	UINT32 x, y;
	int rc = -1;
	encoder = bitmap_interleaved_context_new(TRUE);
	decoder = bitmap_interleaved_context_new(FALSE);

	if (!encoder || !decoder)
		goto fail;

	for (x = 0; x < 100; x++)
	{
		if (!run_encode_decode(24, encoder, decoder))
			goto fail;

		if (!run_encode_decode(16, encoder, decoder))
			goto fail;

		if (!run_encode_decode(15, encoder, decoder))
			goto fail;
	}

	rc = 0;
fail:
	bitmap_interleaved_context_free(encoder);
	bitmap_interleaved_context_free(decoder);
	return rc;
}
