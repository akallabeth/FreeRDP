include(today)
include(GNUInstallDirs)
include(CleaningConfigureFile)

get_filename_component(INSTALL_FREERDP_MAN_SCRIPT_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)

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
                get_target_property(name_base "${target}" OUTPUT_NAME)
		set(template "${target}.${section}")
		set(MANPAGE_NAME "${name_base}")
		set(manpage "${name_base}.${section}")

		# We need the variable ${MAN_TODAY} to contain the current date in ISO
		# format to replace it in the cleaning_configure_file step.
		include(today)

		TODAY(MAN_TODAY)

                set(GENERATE_COMMAND -Dtemplate=\"${template}\" -DMANPAGE_NAME=\"${MANPAGE_NAME}\" -Dmanpage=\"${manpage}\" -DMAN_TODAY=\"${MAN_TODAY}\" -DCURRENT_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\" -DCURRENT_BINARY_DIR=\"${CMAKE_CURRENT_BINARY_DIR}\" -Dtarget="${target}" -Dsection="${section}" -Ddependencies="${dependencies}" -P \"${INSTALL_FREERDP_MAN_SCRIPT_DIR}/GenerateManpages.cmake\")

                add_custom_target(${manpage}.target ALL
                    COMMAND ${CMAKE_COMMAND} ${GENERATE_COMMAND}
                    DEPENDS ${MAN_OPTIONS_FILE}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                )

		install_freerdp_man(${CMAKE_CURRENT_BINARY_DIR}/${manpage} ${section})
	endif()
endfunction()
