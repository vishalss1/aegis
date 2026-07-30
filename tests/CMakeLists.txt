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

add_custom_target(check
    COMMAND test_packet
    COMMAND test_transport
    COMMAND test_crypto
    COMMENT "Running all unit tests"
)
