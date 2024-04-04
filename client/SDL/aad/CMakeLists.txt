set(WITH_WEBVIEW_DEFAULT OFF)
if (UNIX AND NOT APPLE)
    set(WITH_WEBVIEW_DEFAULT ON)
endif()

option(WITH_WEBVIEW "Build with WebView support for AAD login popup browser" ${WITH_WEBVIEW_DEFAULT})
if (WITH_WEBVIEW)
  option(WITH_WEBVIEW_QT "Build with QtWebEngine support for AAD login broweser popup" OFF)

  set(SRCS
    sdl_webview.hpp
    webview_impl.hpp
    sdl_webview.cpp
  )
  set(LIBS
    winpr
  )

  if (WITH_WEBVIEW_QT)
    find_package(Qt5 COMPONENTS WebEngineWidgets REQUIRED)

    list(APPEND SRCS
      qt/webview_impl.cpp
    )

    list(APPEND LIBS
      Qt5::WebEngineWidgets
    )
  else()
    include(ExternalProjectWebview)
    list(APPEND SRCS
      wrapper/webview_impl.cpp
    )
    list(APPEND LIBS
      webview
    )
  endif()
else()
  set(SRCS
    dummy.cpp
  )
endif()

configure_file(sdl_config.hpp.in sdl_config.hpp @ONLY)

add_library(aad-view STATIC
  ${SRCS}
)
target_include_directories(aad-view PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(aad-view
  PRIVATE
  ${LIBS}
)
target_compile_definitions(
  aad-view
  PUBLIC
  ${DEFINITIONS}
)

