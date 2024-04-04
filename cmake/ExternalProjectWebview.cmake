include(FetchContent)

FetchContent_Declare(
        webview
        GIT_REPOSITORY https://github.com/webview/webview.git
        GIT_TAG adbb85d0f54537b8034ece0bab67c7d1438e3cda
)

FetchContent_GetProperties(webview)
if (NOT webview_POPULATED)
    # Library does not have a CMake build script
    # We have to do it ourselves
    FetchContent_Populate(webview)
    add_library(webview INTERFACE)
    target_sources(webview INTERFACE ${webview_SOURCE_DIR}/webview.h)
    target_include_directories(webview INTERFACE ${webview_SOURCE_DIR})

    # Set compile options
    # See: https://github.com/webview/webview/blob/master/script/build.sh
    if (WIN32)
        file(DOWNLOAD
            https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
            ${CMAKE_CURRENT_BINARY_DIR}/nuget.exe
            SHA256=82bb13e2365e1e5ee7d0975618dcf90b279427de8a7ecb338b9b78bfc457d51b
            SHOW_PROGRESS
        )

        target_compile_definitions(webview INTERFACE WEBVIEW_EDGE)
        # See: https://github.com/webview/webview/blob/master/script/build.bat
        # TODO: fix path or directly fetch lib.
        target_link_libraries(webview INTERFACE "-mwindows -L./dll/x64 -lwebview -lWebView2Loader")
        # target_compile_options(...) ?
    elseif (APPLE)
        target_compile_definitions(webview INTERFACE WEBVIEW_COCOA)
        target_compile_definitions(webview INTERFACE "GUI_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")
        target_link_libraries(webview INTERFACE "-framework Webkit")
    elseif (UNIX)
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(WEBVIEW_GTK webkit2gtk-4.0 REQUIRED)
        target_compile_definitions(webview INTERFACE WEBVIEW_GTK)
        target_include_directories(webview INTERFACE "${WEBVIEW_GTK_INCLUDE_DIRS}")
        target_link_libraries(webview INTERFACE "${WEBVIEW_GTK_LIBRARIES}")
    endif ()
endif ()
