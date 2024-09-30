# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(ClearKey)

cmake_minimum_required(VERSION 3.15)

find_package(Thunder)
project_version(1.0.0)

set(MODULE_NAME ${NAMESPACE}${PROJECT_NAME})

message("Setup ${MODULE_NAME} v${PROJECT_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

if(BUILD_REFERENCE)
    add_definitions(-DBUILD_REFERENCE=${BUILD_REFERENCE})
endif()

option(OPTEE_AES_DECRYPTOR "Enable AES Decryption on OP-TEE environment" OFF)

if(OPTEE_AES_DECRYPTOR)
find_package(OPTEEClearKey REQUIRED)
    add_compile_definitions(OPTEE_AES128)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(${MODULE_NAME}
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto)

endif()

add_library(${MODULE_NAME} SHARED
    MediaSession.cpp 
    MediaSystem.cpp
    JSONWebKey.cpp
    jsmn/jsmn.c
)

set_target_properties(${MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES)

target_compile_options (${MODULE_NAME} PRIVATE -Wno-psabi)

install(TARGETS ${MODULE_NAME}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/${STORAGE_DIRECTORY}/plugins COMPONENT ${NAMESPACE}_Runtime)

target_include_directories(${MODULE_NAME}
    PRIVATE
        ${CMAKE_SYSROOT}${CMAKE_INSTALL_PREFIX}/include/${NAMESPACE}
        "./jsmn")

set_target_properties(${MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED YES)

# Library installation section
set_target_properties(${MODULE_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${MODULE_NAME} PROPERTIES PREFIX "")

install(TARGETS ${MODULE_NAME}
    PERMISSIONS OWNER_READ GROUP_READ
    DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

