set(NOISE_C_SOURCES
    src/protocol/cipherstate.c
    src/protocol/dhstate.c
    src/protocol/errors.c
    src/protocol/handshakestate.c
    src/protocol/hashstate.c
    src/protocol/names.c
    src/protocol/patterns.c
    src/protocol/rand_os.c
    src/protocol/randstate.c
    src/protocol/symmetricstate.c
    src/protocol/unsupported.c
    src/protocol/util.c
    src/backend/ref/cipher-chachapoly.c
    src/backend/ref/dh-curve25519.c
    src/backend/ref/hash-blake2s.c
    src/crypto/blake2/blake2s.c
    src/crypto/chacha/chacha.c
    src/crypto/donna/poly1305-donna.c
    src/crypto/ed25519/ed25519.c
    src/crypto/sha2/sha256.c
)

add_library(noise_protocol STATIC ${NOISE_C_SOURCES})
add_library(NoiseC::Protocol ALIAS noise_protocol)

target_include_directories(noise_protocol
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol
)

target_link_libraries(noise_protocol PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(noise_protocol PRIVATE advapi32)
endif()

# Keep upstream C diagnostics separate from Aegis's warning policy. The Aegis
# wrapper and tests remain compiled with /W4 /WX (or the GCC/Clang equivalent).
if(MSVC)
    target_compile_options(noise_protocol PRIVATE /W3)
else()
    target_compile_options(noise_protocol PRIVATE -Wall -Wextra)
endif()

set_target_properties(noise_protocol PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
