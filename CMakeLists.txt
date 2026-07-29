cmake_minimum_required(VERSION 3.20)
project(aegis
    VERSION 0.1.0
    DESCRIPTION "Aegis — Windows-native secure overlay network mesh"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(PkgConfig QUIET)

# Wintun — downloaded or provided by the user
if(NOT DEFINED WINTUN_DIR)
    set(WINTUN_DIR "${CMAKE_SOURCE_DIR}/wintun" CACHE PATH "Path to Wintun SDK directory")
endif()
if(EXISTS "${WINTUN_DIR}/include/wintun.h")
    add_library(wintun INTERFACE)
    target_include_directories(wintun INTERFACE "${WINTUN_DIR}/include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(WINTUN_LIB_DIR "${WINTUN_DIR}/bin/amd64")
    else()
        set(WINTUN_LIB_DIR "${WINTUN_DIR}/bin/x86")
    endif()
    target_link_directories(wintun INTERFACE "${WINTUN_LIB_DIR}")
    target_link_libraries(wintun INTERFACE wintun)
else()
    message(FATAL_ERROR "Wintun SDK not found in ${WINTUN_DIR}. "
        "Download from https://www.wintun.net/ and set WINTUN_DIR.")
endif()

# Source files — all modules
set(AEGIS_SOURCES
    src/main.cpp
    src/adapter/adapter.cpp
    src/identity/identity.cpp
    src/crypto/crypto.cpp
    src/session/session.cpp
    src/transport/transport.cpp
    src/routing/routing.cpp
    src/peer/peer.cpp
    src/packet/packet.cpp
    src/config/config.cpp
    src/platform/platform.cpp
)

add_executable(aegis ${AEGIS_SOURCES})

target_include_directories(aegis PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(aegis PRIVATE
    wintun
    ws2_32
    iphlpapi
)

# Optional: libsodium or OpenSSL for crypto — user chooses at configure time
option(AEGIS_USE_LIBSODIUM "Use libsodium for X25519/ChaCha20-Poly1305" ON)
option(AEGIS_USE_OPENSSL "Use OpenSSL EVP for X25519/ChaCha20-Poly1305" OFF)

if(AEGIS_USE_LIBSODIUM)
    find_package(libsodium QUIET)
    if(libsodium_FOUND)
        target_link_libraries(aegis PRIVATE libsodium)
        target_compile_definitions(aegis PRIVATE AEGIS_USE_LIBSODIUM)
    else()
        message(FATAL_ERROR "libsodium not found. Install it or set AEGIS_USE_LIBSODIUM=OFF.")
    endif()
elseif(AEGIS_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(aegis PRIVATE OpenSSL::Crypto)
    target_compile_definitions(aegis PRIVATE AEGIS_USE_OPENSSL)
endif()

# Tests
enable_testing()
add_subdirectory(tests)
