get_filename_component(GENERATE_MANPAGES_SCRIPT_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
list(APPEND CMAKE_MODULE_PATH ${GENERATE_MANPAGES_SCRIPT_DIR})

include(CleaningConfigureFile)

set(SRC "${CURRENT_SOURCE_DIR}/${target}.${section}.in")
cleaning_configure_file(${SRC} ${manpage}.tmp @ONLY IMMEDIATE)

# write header (aka name of the manpage), truncate existing
file(READ ${CURRENT_BINARY_DIR}/${manpage}.tmp CONTENTS)
file(WRITE ${CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")

string(REPLACE " " ";" DEPS ${dependencies})
foreach(DEP IN LISTS DEPS)
	get_filename_component(DNAME "${DEP}" NAME)
	set(SRC_IN ${CURRENT_SOURCE_DIR}/${DEP}.in)
	set(SRC ${CURRENT_SOURCE_DIR}/${DEP})
	set(DST ${CURRENT_BINARY_DIR}/${DNAME})

	if (EXISTS ${SRC_IN})
		message("using generated ${DST} from ${SRC_IN}")
		cleaning_configure_file(${SRC_IN} ${DST} @ONLY IMMEDIATE)
	endif()
	if (EXISTS ${SRC})
		message("xxxxxxxxaaaa ${SRC}")
		set(DST ${SRC})
		message("using ${DST}")
	else()
		message("using ${DST}")
	endif()

	file(READ ${DST} CONTENTS)
	file(APPEND ${CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")
endforeach()
