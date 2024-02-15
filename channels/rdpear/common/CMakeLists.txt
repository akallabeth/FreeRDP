# FreeRDP: A Remote Desktop Protocol Implementation
# FreeRDP cmake build script
#
# Copyright 2024 David Fort <contact@hardening-consulting.com>
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

add_library(rdpear-common STATIC
    ndr.c
    rdpear_asn1.c
    rdpear_common.c
)

target_include_directories(rdpear-common PRIVATE ${KRB5_INCLUDE_DIRS})
target_link_directories(rdpear-common PUBLIC ${KRB5_LIBRARY_DIRS})
target_link_libraries(rdpear-common ${KRB5_LIBRARIES})


channel_install(rdpear-common ${FREERDP_ADDIN_PATH} "FreeRDPTargets")

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
