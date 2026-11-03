# WinPR: Windows Portable Runtime
# libwinpr-thread cmake build script
#
# Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

winpr_module_add(
  apc.h
  apc.c
  argv.c
  process.c
  processor.c
  procthreadattr.c
  thread.c
  thread.h
)

set(WINPR_DEFAULT_THREAD_STACK_SIZE
    "1048576"
    CACHE
      STRING
      "default thread stack size (1MB) See https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size"
)
winpr_library_add_compile_options(-DWINPR_DEFAULT_THREAD_STACK_SIZE=${WINPR_DEFAULT_THREAD_STACK_SIZE})

# tls.c only provides a pthread-based TlsAlloc/TlsGetValue/TlsSetValue/TlsFree
# fallback for non-Windows targets. On Cygwin the real system TlsAlloc family
# is available from libkernel32.a, so skip compiling it there instead of
# growing the file's own platform guard.
if(NOT CYGWIN)
  winpr_module_add(tls.c)
endif()

if(BUILD_TESTING)
  add_subdirectory(test)
endif()
