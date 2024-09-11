# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP SDL Client
#
# Copyright 2024 Armin Novak <anovak@thincast.com>
# Copyright 2024 Thincast Technologies GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
    list(APPEND SRCS
      wrapper/webview_impl.cpp
    )

    find_package(webview REQUIRED)
    list(APPEND LIBS
        webview::core_static
    )
include(ListTargetProperties)
list_target_properties(webview::core_static)
  endif()
else()
  set(SRCS
    dummy.cpp
  )
endif()

configure_file(sdl_config.hpp.in sdl_config.hpp @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(sdl-common-aad-view INTERFACE)
add_library(sdl-common-aad-view-obj OBJECT
    ${SRCS}
)
target_include_directories(sdl-common-aad-view INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(sdl-common-aad-view
  INTERFACE
  ${LIBS}
  sdl-common-aad-view-obj
)
target_compile_definitions(
  sdl-common-aad-view
  INTERFACE
  ${DEFINITIONS}
)

