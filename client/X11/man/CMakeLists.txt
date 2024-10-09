set(DEPS
        xfreerdp-channels.1.in
        xfreerdp-examples.1.in
        xfreerdp-shortcuts.1.in
        xfreerdp-envvar.1.in
        xfreerdp-links.1.in
        #../../common/man/freerdp-global-config.1.xml
)

generate_and_install_freerdp_man_from_xml(${MODULE_NAME} "1" "${DEPS}")
