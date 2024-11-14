include(CheckAndSetFlag)

option(ENABLE_WARNING_VERBOSE "enable -Weveryting (and some exceptions) for compile" OFF)
option(ENABLE_WARNING_ERROR "enable -Werror for compile" OFF)

if (ENABLE_WARNING_VERBOSE)
	if (MSVC)
		# Remove previous warning definitions,
		# NMake is otherwise complaining.
		foreach (flags_var_to_scrub
			CMAKE_C_FLAGS
			CMAKE_C_FLAGS_DEBUG
			CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_RELWITHDEBINFO
			CMAKE_C_FLAGS_MINSIZEREL)
			string (REGEX REPLACE "(^| )[/-]W[ ]*[1-9]" " "
			"${flags_var_to_scrub}" "${${flags_var_to_scrub}}")
		endforeach()
	else()
		set(C_WARNING_FLAGS
			-Wno-pre-c11-compat
			-Wno-gnu-zero-variadic-macro-arguments
		)
	endif()

	foreach(FLAG ${C_WARNING_FLAGS})
		CheckAndSetFlag(${FLAG})
	endforeach()
endif()

CheckAndSetFlag(-Wimplicit-function-declaration)

# Android profiling
if(ANDROID)
	if(WITH_GPROF)
        CheckAndSetFlag(-pg)
		set(PROFILER_LIBRARIES
			"${FREERDP_EXTERNAL_PROFILER_PATH}/obj/local/${ANDROID_ABI}/libandroid-ndk-profiler.a")
		include_directories(SYSTEM "${FREERDP_EXTERNAL_PROFILER_PATH}")
	endif()
endif()

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} CACHE STRING "default CFLAGS")
message("Using CFLAGS ${CMAKE_C_FLAGS}")
