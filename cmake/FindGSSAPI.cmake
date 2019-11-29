# - Try to find the GSS Kerberos libraries
# Once done this will define
#
#  GSSAPI_ROOT_DIR - Set this variable to the root installation of GSS
#  GSSAPI_ROOT_FLAVOUR - Set this variable to the flavour of Kerberos installation (MIT or Heimdal)
#
# Read-Only variables:
#  GSSAPI_FOUND - system has the Heimdal library
#  GSSAPI_FLAVOUR - "MIT" or "Heimdal" if anything found.
#  GSSAPI_INCLUDE_DIR - the Heimdal include directory
#  GSSAPI_LIBRARIES - The libraries needed to use GSS
#  GSSAPI_LINK_DIRECTORIES - Directories to add to linker search path
#  GSSAPI_LINKER_FLAGS - Additional linker flags
#  GSSAPI_COMPILER_FLAGS - Additional compiler flags
#  GSSAPI_VERSION - This is set to version advertised by pkg-config or read from manifest.
#                In case the library is found but no version info availabe it'll be set to "unknown"

set(_MIT_MODNAME mit-krb5-gssapi)
set(_HEIMDAL_MODNAME heimdal-gssapi)

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

# export GSSAPI_ROOT_FLAVOUR to use pkg-config system under UNIX
if(UNIX)
  if(NOT "$ENV{GSSAPI_ROOT_FLAVOUR}" STREQUAL "")
    string(REGEX MATCH "^[M|m]it$" MIT_FLAVOUR "$ENV{GSSAPI_ROOT_FLAVOUR}")
    if(NOT MIT_FLAVOUR)
      string(REGEX MATCH "^MIT$" MIT_FLAVOUR "$ENV{GSSAPI_ROOT_FLAVOUR}")
    endif()
    string(REGEX MATCH "^[H|h]eimdal$" HEIMDAL_FLAVOUR "$ENV{GSSAPI_ROOT_FLAVOUR}")
    if(NOT HEIMDAL_FLAVOUR)
      string(REGEX MATCH "^HEIMDAL$" HEIMDAL_FLAVOUR "$ENV{GSSAPI_ROOT_FLAVOUR}")
    endif()
    if(MIT_FLAVOUR)
      set(GSSAPI_FLAVOUR "MIT")
    elseif(HEIMDAL_FLAVOUR)
      set(GSSAPI_FLAVOUR "Heimdal")
    else()
      set(GSSAPI_FLAVOUR "MIT")
    endif()
  else()
    set(GSSAPI_FLAVOUR "MIT")
  endif()
  set(ENV{GSSAPI_ROOT_FLAVOUR} ${GSSAPI_FLAVOUR})
endif()

set(_GSSAPI_ROOT_HINTS
    "${GSSAPI_ROOT_DIR}"
    "$ENV{GSSAPI_ROOT_DIR}"
)

# try to find library using system pkg-config if user did not specify root dir
if(UNIX)
    if(GSSAPI_FLAVOUR)
      find_package(PkgConfig QUIET REQUIRED)
      if(GSSAPI_FLAVOUR STREQUAL "MIT")
        pkg_search_module(_GSSAPI_PKG REQUIRED ${_MIT_MODNAME})
      elseif(GSSAPI_FLAVOUR STREQUAL "Heimdal")
        pkg_search_module(_GSSAPI_PKG REQUIRED ${_HEIMDAL_MODNAME})
      else()
        message(FATAL_ERROR "Invalid GSSAPI_FLAVOUR=${GSSAPI_FLAVOUR}")
      endif()

      list(APPEND _GSSAPI_PKG_INCLUDE_DIRS ${_GSSAPI_PKG_INCLUDEDIR})
      list(APPEND _GSSAPI_ROOT_HINTS "${_GSSAPI_PKG_INCLUDE_DIRS}")
      list(APPEND _GSSAPI_ROOT_HINTS "${_GSSAPI_PKG_PREFIX}")
    else()
      message(WARNING "set GSSAPI_FLAVOUR to use pkg-config")
    endif()
elseif(WIN32)
  list(APPEND _GSSAPI_ROOT_HINTS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
endif()

if(NOT _GSSAPI_PKG_FOUND) # not found by pkg-config. Let's take more traditional approach.
  find_file(_GSSAPI_CONFIGURE_SCRIPT
      NAMES
          "krb5-config"
      HINTS
          ${_GSSAPI_ROOT_HINTS}
      PATH_SUFFIXES
          bin
      NO_CMAKE_PATH
      NO_CMAKE_ENVIRONMENT_PATH
  )

  # if not found in user-supplied directories, maybe system knows better
  find_file(_GSSAPI_CONFIGURE_SCRIPT
      NAMES
          "krb5-config"
      PATH_SUFFIXES
          bin
  )

  execute_process(
       COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--vendor"
       OUTPUT_VARIABLE _GSSAPI_VENDOR
       RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
  )

  if(NOT _GSSAPI_CONFIGURE_FAILED)
    string(STRIP "${_GSSAPI_VENDOR}" _GSSAPI_VENDOR)
    if((GSSAPI_FLAVOUR STREQUAL "Heimdal" AND NOT _GSSAPI_VENDOR STREQUAL "Heimdal")
       OR (GSSAPI_FLAVOUR STREQUAL "MIT" AND NOT _GSSAPI_VENDOR STREQUAL "Massachusetts Institute of Technology"))
      message(SEND_ERROR "GSS vendor and GSS flavour are not matching : _GSSAPI_VENDOR=${_GSSAPI_VENDOR} ; GSSAPI_FLAVOUR=${GSSAPI_FLAVOUR}")
      message(STATUS "Try to set the path to GSS root folder in the system variable GSSAPI_ROOT_DIR")
    endif()
  else()
    message(SEND_ERROR "GSS configure script failed to get vendor")
  endif()

  # NOTE: fail to link Heimdal libraries using configure script due to limitations
  # during Heimdal linking process. Then, we do it "manually".
  if(NOT "${_GSSAPI_CONFIGURE_SCRIPT} " STREQUAL " " AND GSSAPI_FLAVOUR AND NOT _GSSAPI_VENDOR STREQUAL "Heimdal")
    execute_process(
          COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--cflags" "gssapi"
          OUTPUT_VARIABLE _GSSAPI_CFLAGS
          RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
    )

    if(NOT _GSSAPI_CONFIGURE_FAILED) # 0 means success
      # should also work in an odd case when multiple directories are given
      string(STRIP "${_GSSAPI_CFLAGS}" _GSSAPI_CFLAGS)
      string(REGEX REPLACE " +-I" ";" _GSSAPI_CFLAGS "${_GSSAPI_CFLAGS}")
      string(REGEX REPLACE " +-([^I][^ \\t;]*)" ";-\\1" _GSSAPI_CFLAGS "${_GSSAPI_CFLAGS}")

      foreach(_flag ${_GSSAPI_CFLAGS})
        if(_flag MATCHES "^-I.*")
          string(REGEX REPLACE "^-I" "" _val "${_flag}")
          list(APPEND _GSSAPI_INCLUDE_DIR "${_val}")
        else()
          list(APPEND _GSSAPI_COMPILER_FLAGS "${_flag}")
        endif()
      endforeach()
    endif()

    if(_GSSAPI_VENDOR STREQUAL "Massachusetts Institute of Technology")
      execute_process(
            COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--libs" "gssapi"
            OUTPUT_VARIABLE _GSSAPI_LIB_FLAGS
            RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
      )
    elseif(_GSSAPI_VENDOR STREQUAL "Heimdal")
      execute_process(
            COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--deps --libs" "gssapi kafs"
            OUTPUT_VARIABLE _GSSAPI_LIB_FLAGS
            RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
      )
    else()
      message(SEND_ERROR "Unknown vendor")
    endif()

    if(NOT _GSSAPI_CONFIGURE_FAILED) # 0 means success
      # this script gives us libraries and link directories. We have to deal with it.
      string(STRIP "${_GSSAPI_LIB_FLAGS}" _GSSAPI_LIB_FLAGS)
      string(REGEX REPLACE " +-(L|l)" ";-\\1" _GSSAPI_LIB_FLAGS "${_GSSAPI_LIB_FLAGS}")
      string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _GSSAPI_LIB_FLAGS "${_GSSAPI_LIB_FLAGS}")

      foreach(_flag ${_GSSAPI_LIB_FLAGS})
        if(_flag MATCHES "^-l.*")
          string(REGEX REPLACE "^-l" "" _val "${_flag}")
          list(APPEND _GSSAPI_LIBRARIES "${_val}")
        elseif(_flag MATCHES "^-L.*")
          string(REGEX REPLACE "^-L" "" _val "${_flag}")
          list(APPEND _GSSAPI_LINK_DIRECTORIES "${_val}")
        else()
          list(APPEND _GSSAPI_LINKER_FLAGS "${_flag}")
        endif()
      endforeach()

    endif()

    execute_process(
          COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--version"
          OUTPUT_VARIABLE _GSSAPI_VERSION
          RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
    )

    # older versions may not have the "--version" parameter. In this case we just don't care.
    if(_GSSAPI_CONFIGURE_FAILED)
      set(_GSSAPI_VERSION 0)
    endif()

  else() # either there is no config script or we are on platform that doesn't provide one (Windows?)
    if(_GSSAPI_VENDOR STREQUAL "Massachusetts Institute of Technology")
      find_path(_GSSAPI_INCLUDE_DIR
               NAMES
                   "gssapi/gssapi_generic.h"
               HINTS
                   ${_GSSAPI_ROOT_HINTS}
               PATH_SUFFIXES
                   include
                   inc
      )

      if(_GSSAPI_INCLUDE_DIR) # we've found something
        set(CMAKE_REQUIRED_INCLUDES "${_GSSAPI_INCLUDE_DIR}")
        check_include_files( "gssapi/gssapi_generic.h;gssapi/gssapi_ext.h" _GSSAPI_HAVE_MIT_HEADERS)
        if(_GSSAPI_HAVE_MIT_HEADERS)
          set(GSSAPI_FLAVOUR "MIT")
        else()
          message(SEND_ERROR "Try to set the Kerberos flavour (GSSAPI_FLAVOUR)")
        endif()
      elseif("$ENV{PKG_CONFIG_PATH} " STREQUAL " ")
        message(WARNING "Try to set PKG_CONFIG_PATH to PREFIX_OF_KERBEROS/lib/pkgconfig")
      endif()
    elseif(_GSSAPI_VENDOR STREQUAL "Heimdal")
      find_path(_GSSAPI_INCLUDE_DIR
               NAMES
                   "gssapi/gssapi_spnego.h"
               HINTS
                   ${_GSSAPI_ROOT_HINTS}
               PATHS
                   /usr/heimdal
                   /usr/local/heimdal
               PATH_SUFFIXES
                   include
                   inc
      )

      if(_GSSAPI_INCLUDE_DIR) # we've found something
        set(CMAKE_REQUIRED_INCLUDES "${_GSSAPI_INCLUDE_DIR}")
        # prevent compiling the header - just check if we can include it
        set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D__ROKEN_H__")
        check_include_file( "roken.h" _GSSAPI_HAVE_ROKEN_H)
        check_include_file( "heimdal/roken.h" _GSSAPI_HAVE_HEIMDAL_ROKEN_H)
        if(_GSSAPI_HAVE_ROKEN_H OR _GSSAPI_HAVE_HEIMDAL_ROKEN_H)
          set(GSSAPI_FLAVOUR "Heimdal")
        endif()
        set(CMAKE_REQUIRED_DEFINITIONS "")
      elseif("$ENV{PKG_CONFIG_PATH} " STREQUAL " ")
        message(WARNING "Try to set PKG_CONFIG_PATH to PREFIX_OF_KERBEROS/lib/pkgconfig")
      endif()
    else()
      message(SEND_ERROR "Kerberos vendor unknown (${_GSSAPI_VENDOR})")
    endif()

    # if we have headers, check if we can link libraries
    if(GSSAPI_FLAVOUR)
      set(_GSSAPI_LIBDIR_SUFFIXES "")
      set(_GSSAPI_LIBDIR_HINTS ${_GSSAPI_ROOT_HINTS})
      get_filename_component(_GSSAPI_CALCULATED_POTENTIAL_ROOT "${_GSSAPI_INCLUDE_DIR}" PATH)
      list(APPEND _GSSAPI_LIBDIR_HINTS ${_GSSAPI_CALCULATED_POTENTIAL_ROOT})

      if(WIN32)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
          list(APPEND _GSSAPI_LIBDIR_SUFFIXES "lib/AMD64")
          if(GSSAPI_FLAVOUR STREQUAL "MIT")
            set(_GSSAPI_LIBNAME "gssapi64")
          else()
            set(_GSSAPI_LIBNAME "libgssapi")
          endif()
        else()
          list(APPEND _GSSAPI_LIBDIR_SUFFIXES "lib/i386")
          if(GSSAPI_FLAVOUR STREQUAL "MIT")
            set(_GSSAPI_LIBNAME "gssapi32")
          else()
            set(_GSSAPI_LIBNAME "libgssapi")
          endif()
        endif()
      else()
        list(APPEND _GSSAPI_LIBDIR_SUFFIXES "lib;lib64;x86_64-linux-gnu") # those suffixes are not checked for HINTS
        if(GSSAPI_FLAVOUR STREQUAL "MIT")
          set(_GSSAPI_LIBNAME "gssapi_krb5")
          set(_KRB5_LIBNAME "krb5")
          set(_COMERR_LIBNAME "com_err")
          set(_KRB5SUPPORT_LIBNAME "krb5support")
        else()
          set(_GSSAPI_LIBNAME "gssapi")
          set(_KRB5_LIBNAME "krb5")
          set(_KAFS_LIBNAME "kafs")
          set(_ROKEN_LIBNAME "roken")
        endif()
      endif()

      find_library(_GSSAPI_LIBRARIES
                  NAMES
                      ${_GSSAPI_LIBNAME}
                  HINTS
                      ${_GSSAPI_LIBDIR_HINTS}
                  PATH_SUFFIXES
                      ${_GSSAPI_LIBDIR_SUFFIXES}
      )

      if(GSSAPI_FLAVOUR STREQUAL "MIT")
        find_library(_KRB5_LIBRARY
                    NAMES
                        ${_KRB5_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        find_library(_COMERR_LIBRARY
                    NAMES
                        ${_COMERR_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        find_library(_KRB5SUPPORT_LIBRARY
                    NAMES
                        ${_KRB5SUPPORT_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        list(APPEND _GSSAPI_LIBRARIES ${_KRB5_LIBRARY} ${_KRB5SUPPORT_LIBRARY} ${_COMERR_LIBRARY})
      endif()

      if(GSSAPI_FLAVOUR STREQUAL "Heimdal")
        find_library(_KRB5_LIBRARY
                    NAMES
                        ${_KRB5_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        find_library(_KAFS_LIBRARY
                    NAMES
                        ${_KAFS_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        find_library(_ROKEN_LIBRARY
                    NAMES
                        ${_ROKEN_LIBNAME}
                    HINTS
                        ${_GSSAPI_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSSAPI_LIBDIR_SUFFIXES}
        )
        list(APPEND _GSSAPI_LIBRARIES ${_KRB5_LIBRARY} ${_KAFS_LIBRARY} ${_ROKEN_LIBRARY})
      endif()
    endif()

    execute_process(
          COMMAND ${_GSSAPI_CONFIGURE_SCRIPT} "--version"
          OUTPUT_VARIABLE _GSSAPI_VERSION
          RESULT_VARIABLE _GSSAPI_CONFIGURE_FAILED
    )

    # older versions may not have the "--version" parameter. In this case we just don't care.
    if(_GSSAPI_CONFIGURE_FAILED)
      set(_GSSAPI_VERSION 0)
    endif()

  endif()

  set(GSSAPI_INCLUDE_DIR ${_GSSAPI_INCLUDE_DIR})
  set(GSSAPI_LIBRARIES ${_GSSAPI_LIBRARIES})
  set(GSSAPI_LINK_DIRECTORIES ${_GSSAPI_LINK_DIRECTORIES})
  set(GSSAPI_LINKER_FLAGS ${_GSSAPI_LINKER_FLAGS})
  set(GSSAPI_COMPILER_FLAGS ${_GSSAPI_COMPILER_FLAGS})
  set(GSSAPI_VERSION ${_GSSAPI_VERSION})
else()
  set(_GSSAPI_VERSION _GSSAPI_PKG_VERSION)
  set(GSSAPI_INCLUDE_DIR ${_GSSAPI_PKG_INCLUDE_DIRS})
  set(GSSAPI_LIBRARIES ${_GSSAPI_PKG_LIBRARIES})
  set(GSSAPI_LINK_DIRECTORIES ${_GSSAPI_PKG_LIBRARY_DIRS})
  set(GSSAPI_LINKER_FLAGS ${_GSSAPI_PKG_LDFLAGS})
  set(GSSAPI_COMPILER_FLAGS ${_GSSAPI_PKG_CFLAGS})
  set(GSSAPI_VERSION ${_GSSAPI_VERSION})
endif()

include(FindPackageHandleStandardArgs)

set(_GSSAPI_REQUIRED_VARS GSSAPI_LIBRARIES GSSAPI_INCLUDE_DIR GSSAPI_LINK_DIRECTORIES GSSAPI_LINKER_FLAGS GSSAPI_COMPILER_FLAGS GSSAPI_VERSION)

find_package_handle_standard_args(GSSAPI
    REQUIRED_VARS
        ${_GSSAPI_REQUIRED_VARS}
    VERSION_VAR
        GSSAPI_VERSION
    FAIL_MESSAGE
    "Could NOT find GSSAPI, try to set the path to GSSAPI root folder in the system variable GSSAPI_ROOT_DIR"
)

mark_as_advanced(GSSAPI_INCLUDE_DIR GSSAPI_LIBRARIES)
