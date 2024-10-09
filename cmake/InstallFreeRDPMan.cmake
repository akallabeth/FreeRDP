include(GNUInstallDirs)
include(CleaningConfigureFile)

function(install_freerdp_man manpage section)
	if(WITH_MANPAGES)
		install(FILES ${manpage} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${section})
	endif()
endfunction()

function(generate_and_install_freerdp_man_from_template name_base section api)
	if(WITH_MANPAGES)
		if (WITH_BINARY_VERSIONING)
			set(manpage "${CMAKE_CURRENT_BINARY_DIR}/${name_base}${api}.${section}")
		else()
			set(manpage "${CMAKE_CURRENT_BINARY_DIR}/${name_base}.${section}")
		endif()
                cleaning_configure_file(${name_base}.${section}.in ${manpage})
		install_freerdp_man(${manpage} ${section})
	endif()
endfunction()

function(generate_and_install_freerdp_man_from_xml target section dependencies)
	if(WITH_MANPAGES)
		get_target_property(name_base ${target} OUTPUT_NAME)
		set(template "${target}.${section}")
		set(MANPAGE_NAME "${name_base}")
		set(manpage "${name_base}.${section}")

		# We need the variable ${MAN_TODAY} to contain the current date in ISO
		# format to replace it in the cleaning_configure_file step.
		include(today)

		TODAY(MAN_TODAY)

		cleaning_configure_file(${template}.in ${manpage}.tmp @ONLY IMMEDIATE)

		# write header (aka name of the manpage), truncate existing
		file(READ ${CMAKE_CURRENT_BINARY_DIR}/${manpage}.tmp CONTENTS)
		file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")

		foreach(DEP IN LISTS dependencies)
			get_filename_component(DNAME "${DEP}" NAME)
			set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/${DEP}.in)
			set(DST ${CMAKE_CURRENT_BINARY_DIR}/${DNAME})

			if (EXISTS ${SRC})
				message("generating ${DST} from ${SRC}")
				cleaning_configure_file(${SRC} ${DST} @ONLY IMMEDIATE)
			else()
				message("using ${DST} from ${SRC}")
			endif()

			file(READ ${DST} CONTENTS)
			file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/${manpage} "${CONTENTS}")
		endforeach()

		install_freerdp_man(${CMAKE_CURRENT_BINARY_DIR}/${manpage} ${section})
	endif()
endfunction()
