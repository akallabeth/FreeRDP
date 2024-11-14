include(CheckAndSetFlag)

option(ENABLE_WARNING_VERBOSE "enable -Weveryting (and some exceptions) for compile" OFF)
option(ENABLE_WARNING_ERROR "enable -Werror for compile" OFF)

if (ENABLE_WARNING_VERBOSE)
    if (MSVC)
		set(C_WARNING_FLAGS
			/W4
			/wo4324
		)
	else()
		set(C_WARNING_FLAGS
			-Weverything
			-Wall
			-Wpedantic
			-Wno-padded
			-Wno-switch-enum
			-Wno-cast-align
			-Wno-declaration-after-statement
			-Wno-unsafe-buffer-usage
			-Wno-reserved-identifier
			-Wno-covered-switch-default
			-Wno-disabled-macro-expansion
		)
	endif()

	foreach(FLAG ${C_WARNING_FLAGS})
		CheckAndSetFlag(${FLAG})
	endforeach()
endif()

if (ENABLE_WARNING_ERROR)
	CheckAndSetFlag(-Werror)
endif()

CheckAndSetFlag(-Wredundant-decls)

include (ExportAllSymbols)

# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53431
if (CMAKE_COMPILER_IS_GNUCC AND (CMAKE_C_COMPILER_VERSION LESS 13))
	CheckAndSetFlag(-Wno-unknown-pragmas)
endif()

include(CompilerSanitizerOptions)

CheckAndSetFlag(-fno-omit-frame-pointer)

CheckAndSetFlag($<$<CONFIG:Release>:-fmacro-prefix-map="${CMAKE_SOURCE_DIR}"=".">)
CheckAndSetFlag($<$<CONFIG:Release>:--fmacro-prefix-map="${CMAKE_BINARY_DIR}"="./build/">)
CheckAndSetFlag($<$<CONFIG:Release>:--ffile-prefix-map="${CMAKE_SOURCE_DIR}"=".">)
CheckAndSetFlag($<$<CONFIG:Release>:--ffile-prefix-map="${CMAKE_BINARY_DIR}"="./build">)


