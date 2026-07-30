add_executable(test_packet test_packet.cpp ../src/packet/packet.cpp)
target_include_directories(test_packet PRIVATE ../include)

add_test(NAME test_packet COMMAND test_packet)

add_executable(test_transport test_transport.cpp ../src/transport/transport.cpp ../src/platform/platform.cpp)
target_include_directories(test_transport PRIVATE ../include)
target_link_libraries(test_transport ws2_32)

add_test(NAME test_transport COMMAND test_transport)

add_executable(test_crypto test_crypto.cpp ../src/crypto/x25519.cpp)
target_include_directories(test_crypto PRIVATE ../include)
target_link_libraries(test_crypto OpenSSL::Crypto)
add_test(NAME test_crypto COMMAND test_crypto)

add_executable(test_aead test_aead.cpp ../src/crypto/chacha20poly1305.cpp)
target_include_directories(test_aead PRIVATE ../include)
target_link_libraries(test_aead OpenSSL::Crypto)
add_test(NAME test_aead COMMAND test_aead)

add_executable(test_identity test_identity.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp)
target_include_directories(test_identity PRIVATE ../include)
target_link_libraries(test_identity OpenSSL::Crypto)
add_test(NAME test_identity COMMAND test_identity)

add_executable(test_tunnel test_tunnel.cpp ../src/crypto/chacha20poly1305.cpp)
target_include_directories(test_tunnel PRIVATE ../include)
target_link_libraries(test_tunnel OpenSSL::Crypto)
add_test(NAME test_tunnel COMMAND test_tunnel)

add_custom_target(check
    COMMAND test_packet
    COMMAND test_transport
    COMMAND test_crypto
    COMMAND test_aead
    COMMAND test_identity
    COMMAND test_tunnel
    COMMENT "Running all unit tests"
)
