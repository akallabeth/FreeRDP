set(DEPS
	../../common/man/sdl-freerdp-config.1
	../../../common/man/freerdp-global-options.1
	../../common/man/sdl-freerdp-examples.1
	../../../common/man/freerdp-global-envvar.1
	../../../common/man/freerdp-global-config.1
)

generate_and_install_freerdp_man_from_xml(${MODULE_NAME} "1" "${DEPS}")
