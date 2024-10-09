get_filename_component(GENERATE_MANPAGES_SCRIPT_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
list(APPEND CMAKE_MODULE_PATH ${GENERATE_MANPAGES_SCRIPT_DIR})

include(CleaningConfigureFile)

cleaning_configure_file(${template}.in ${manpage}.tmp @ONLY IMMEDIATE)

# write header (aka name of the manpage), truncate existing
file(READ ${CURRENT_BINARY_DIR}/${manpage}.tmp CONTENTS)
file(WRITE ${CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")

foreach(DEP IN LISTS dependencies)
	get_filename_component(DNAME "${DEP}" NAME)
	set(SRC ${CURRENT_SOURCE_DIR}/${DEP}.in)
	set(DST ${CURRENT_BINARY_DIR}/${DNAME})

	if (EXISTS ${SRC})
		message("generating ${DST} from ${SRC}")
		cleaning_configure_file(${SRC} ${DST} @ONLY IMMEDIATE)
	else()
		message("using ${DST} from ${SRC}")
	endif()

	file(READ ${DST} CONTENTS)
	file(APPEND ${CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")
endforeach()
