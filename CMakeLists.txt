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

# Wintun — downloaded or provided by the user
if(NOT DEFINED WINTUN_DIR)
    set(WINTUN_DIR "${CMAKE_SOURCE_DIR}/wintun" CACHE PATH "Path to Wintun SDK directory")
endif()
if(EXISTS "${WINTUN_DIR}/include/wintun.h")
    add_library(wintun INTERFACE)
    target_include_directories(wintun INTERFACE "${WINTUN_DIR}/include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(WINTUN_DLL "${WINTUN_DIR}/bin/amd64/wintun.dll")
    else()
        set(WINTUN_DLL "${WINTUN_DIR}/bin/x86/wintun.dll")
    endif()
else()
    message(FATAL_ERROR "Wintun SDK not found in ${WINTUN_DIR}. "
        "Download from https://www.wintun.net/ and set WINTUN_DIR.")
endif()

# Source files — all modules
set(AEGIS_SOURCES
    src/main.cpp
    src/adapter/adapter.cpp
    src/identity/identity.cpp
    src/crypto/x25519.cpp
    src/crypto/chacha20poly1305.cpp
    src/tunnel/tunnel.cpp
    src/tunnel/tunnel_test.cpp
    src/session/session.cpp
    src/transport/transport.cpp
    src/routing/routing.cpp
    src/peer/peer.cpp
    src/peer/peer_table.cpp
    src/packet/packet.cpp
    src/packet/relay.cpp
    src/discovery/discovery.cpp
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

# Copy wintun.dll next to the executable (loaded at runtime)
add_custom_command(TARGET aegis POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINTUN_DLL}"
        "$<TARGET_FILE_DIR:aegis>"
    COMMENT "Copying wintun.dll to output directory"
)

# OpenSSL EVP (decided per CLAUDE.md)
find_package(OpenSSL REQUIRED)
target_link_libraries(aegis PRIVATE OpenSSL::Crypto)
target_compile_definitions(aegis PRIVATE AEGIS_USE_OPENSSL)

# Tests
enable_testing()
add_subdirectory(tests)
