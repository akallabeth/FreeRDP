
#include <math.h>

#include <winpr/crt.h>
#include <winpr/print.h>

#include <freerdp/freerdp.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/bitmap.h>
#include <freerdp/codec/interleaved.h>

static BOOL run_encode_decode(BITMAP_INTERLEAVED_CONTEXT* encoder, BITMAP_INTERLEAVED_CONTEXT* decoder)
{
	BOOL rc = FALSE;
	const UINT32 w = 1920;
	const UINT32 h = 1080;
	const size_t step = (w + 13) * 4;
	const size_t SrcSize = step * h;
	BYTE* pSrcData = malloc(SrcSize);
	BYTE* pDstData = malloc(SrcSize);
	BYTE* tmp = malloc(SrcSize);

	if (!pSrcData || !pDstData || !tmp)
		goto fail;

	if (!interleaved_compress(decoder, pDstData, UINT32* pDstSize, w, h,
	                                      const BYTE* pSrcData, UINT32 SrcFormat,
	                                      UINT32 nSrcStep, UINT32 nXSrc, UINT32 nYSrc,
	                                      NULL, UINT32 bpp))
		goto fail;

	if (!interleaved_decompress(encoder, pSrcData, SrcSize, w, h,
	                                        UINT32 bpp,
	                                        BYTE* pDstData, UINT32 DstFormat,
	                                        step, UINT32 nXDst, UINT32 nYDst,
	                                        w, h,
	                                        NULL))
		goto fail;

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
	UINT32 x;
	int rc = -1;

	encoder = bitmap_interleaved_context_new(TRUE);
	decoder = bitmap_interleaved_context_new(FALSE);

	if (!encoder || !decoder)
		goto fail;

	for (x = 0; x < 100; x++)
	{
		if (!bitmap_interleaved_context_reset(encoder) || !bitmap_interleaved_context_reset(decoder))
			goto fail;

		if (!run_encode_decode(encoder, decoder))
			goto fail;
	}

	rc = 0;
    fail:
	bitmap_interleaved_context_new(encoder);
	bitmap_interleaved_context_new(decoder);
	return rc;
}
