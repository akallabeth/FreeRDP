# codec

set(CODEC_SRCS
	bulk.c
	bulk.h
	dsp.c
	color.c
	audio.c
	planar.c
	bitmap.c
	interleaved.c
	progressive.c
	rfx_bitstream.h
	rfx_constants.h
	rfx_decode.c
	rfx_decode.h
	rfx_differential.h
	rfx_dwt.c
	rfx_dwt.h
	rfx_encode.c
	rfx_encode.h
	rfx_quantization.c
	rfx_quantization.h
	rfx_rlgr.c
	rfx_rlgr.h
	rfx_types.h
	rfx.c
	region.c
	nsc.c
	nsc_encode.c
	nsc_encode.h
	nsc_types.h
	ncrush.c
	xcrush.c
	mppc.c
	zgfx.c
	clear.c
	jpeg.c
	h264.c
	yuv.c)

set(CODEC_SSE2_SRCS
	sse/rfx_sse2.c
	sse/rfx_sse2.h
	sse/nsc_sse2.c
	sse/nsc_sse2.h
)

set(CODEC_NEON_SRCS
	neon/rfx_neon.c
	neon/rfx_neon.h
	neon/nsc_neon.c
	neon/nsc_neon.h
)

# Append initializers
list(APPEND CODEC_SRCS ${CODEC_SSE2_SRCS})
list(APPEND CODEC_SRCS ${CODEC_NEON_SRCS})

if(WITH_SSE2)
	if(CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
		freerdp_compile_options_add("-msse2")
	endif()

	if(MSVC)
		freerdp_compile_options_add("/arch:SSE2")
	endif()
endif()

if (WITH_DSP_FFMPEG)
    set(CODEC_SRCS
        ${CODEC_SRCS}
		dsp_ffmpeg.c
		dsp_ffmpeg.h)
        freerdp_include_directory_add(${FFMPEG_INCLUDE_DIRS})
        freerdp_library_add(${FFMPEG_LIBRARIES})
endif (WITH_DSP_FFMPEG)

if (WITH_SOXR)
    freerdp_library_add(${SOXR_LIBRARIES})
    include_directories(${SOXR_INCLUDE_DIR})
endif(WITH_SOXR)

if(GSM_FOUND)
    freerdp_library_add(${GSM_LIBRARIES})
    include_directories(${GSM_INCLUDE_DIRS})
endif()

if(LAME_FOUND)
    freerdp_library_add(${LAME_LIBRARIES})
    include_directories(${LAME_INCLUDE_DIRS})
endif()

set(OPUS_DEFAULT OFF)
if (NOT WITH_DSP_FFMPEG)
    find_package(Opus)
    if (Opus_FOUND)
            set(OPUS_DEFAULT ${OPUS_FOUND})
    else()
        find_package(PkgConfig)
        if (PkgConfig_FOUND)
            pkg_check_modules(OPUS opus)
            set(OPUS_DEFAULT ${OPUS_FOUND})
        endif()
    endif()
endif()

option(WITH_OPUS "compile with opus codec support" ${OPUS_DEFAULT})
if (WITH_OPUS)
    find_package(Opus)
    if (Opus_FOUND)
        freerdp_library_add(Opus::opus)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(OPUS REQUIRED opus)
        if(OPUS_FOUND)
            freerdp_library_add(${OPUS_LIBRARIES})
            include_directories(${OPUS_INCLUDE_DIRS})
	    link_directories(${OPUS_LIBRARY_DIRS})
        endif()
    endif()
endif()

if(FAAD2_FOUND)
    freerdp_library_add(${FAAD2_LIBRARIES})
    include_directories(${FAAD2_INCLUDE_DIRS})
endif()

if(FAAC_FOUND)
    freerdp_library_add(${FAAC_LIBRARIES})
    include_directories(${FAAC_INCLUDE_DIRS})
endif()

if(WITH_NEON)
	check_symbol_exists("_M_AMD64"     ""  MSVC_ARM64)
	check_symbol_exists("__aarch64__"  ""  ARCH_ARM64)

	if (NOT MSVC_ARM64 AND NOT ARCH_ARM64)
		freerdp_compile_options_add("-mfpu=neon")
	endif()
endif()

if(WITH_OPENH264)
	set(CODEC_SRCS ${CODEC_SRCS} h264_openh264.c)
	freerdp_include_directory_add(${OPENH264_INCLUDE_DIR})
	if (NOT WITH_OPENH264_LOADING)
		freerdp_library_add(${OPENH264_LIBRARIES})
	endif (NOT WITH_OPENH264_LOADING)
endif()

if(WITH_VIDEO_FFMPEG)
	set(CODEC_SRCS ${CODEC_SRCS} h264_ffmpeg.c)
	freerdp_include_directory_add(${FFMPEG_INCLUDE_DIRS})
	freerdp_library_add(${FFMPEG_LIBRARIES})
endif()

if(WIN32 AND WITH_MEDIA_FOUNDATION)
	set(CODEC_SRCS ${CODEC_SRCS} h264_mf.c)
endif()

if(ANDROID AND WITH_MEDIACODEC)
	list(APPEND CODEC_SRCS h264_mediacodec.c)

	find_library(MEDIACODEC mediandk REQUIRED)
	freerdp_library_add(${MEDIACODEC})
endif()

freerdp_module_add(${CODEC_SRCS})

if(BUILD_TESTING)
	add_subdirectory(test)
endif()
