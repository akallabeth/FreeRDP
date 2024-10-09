set(DEPS
    # TODO: arguments, generated
    xfreerdp-shortcuts.1
    ../../common/man/freerdp-global-envvar.1
    ../../common/man/freerdp-global-config.1
    xfreerdp-examples.1
    ../../common/man/freerdp-global-links.1
)

set(SDL_WIKI_BASE_URL "https://wiki.libsdl.org/SDL2")
generate_and_install_freerdp_man_from_xml(${MODULE_NAME} "1" "${DEPS}")
