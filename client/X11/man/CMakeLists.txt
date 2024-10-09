set(DEPS
    # TODO: arguments, generated
    xfreerdp-shortcuts.1
    xfreerdp-channels.1
    xfreerdp-envvar.1
    ../../common/man/freerdp-global-config.1
    xfreerdp-examples.1
    xfreerdp-links.1
)

generate_and_install_freerdp_man_from_xml(${MODULE_NAME} "1" "${DEPS}")
