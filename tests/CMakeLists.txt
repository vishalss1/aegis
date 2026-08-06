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

add_executable(test_session test_session.cpp ../src/session/session.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp ../src/platform/logger.cpp)
target_include_directories(test_session PRIVATE ../include)
target_link_libraries(test_session OpenSSL::Crypto)
add_test(NAME test_session COMMAND test_session)

add_executable(test_peer test_peer.cpp ../src/peer/peer.cpp ../src/session/session.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp ../src/platform/logger.cpp)
target_include_directories(test_peer PRIVATE ../include)
target_link_libraries(test_peer OpenSSL::Crypto ws2_32)
add_test(NAME test_peer COMMAND test_peer)

add_executable(test_routing test_routing.cpp ../src/routing/routing.cpp)
target_include_directories(test_routing PRIVATE ../include)
add_test(NAME test_routing COMMAND test_routing)

add_executable(test_peer_table test_peer_table.cpp ../src/peer/peer_table.cpp ../src/peer/peer.cpp ../src/session/session.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp ../src/routing/routing.cpp ../src/platform/logger.cpp)
target_include_directories(test_peer_table PRIVATE ../include)
target_link_libraries(test_peer_table OpenSSL::Crypto ws2_32)
add_test(NAME test_peer_table COMMAND test_peer_table)

add_executable(test_relay test_relay.cpp ../src/packet/relay.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp)
target_include_directories(test_relay PRIVATE ../include)
target_link_libraries(test_relay OpenSSL::Crypto)
add_test(NAME test_relay COMMAND test_relay)

add_executable(test_discovery test_discovery.cpp ../src/discovery/discovery.cpp ../src/session/session.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp ../src/transport/transport.cpp ../src/platform/platform.cpp ../src/platform/logger.cpp)
target_include_directories(test_discovery PRIVATE ../include)
target_link_libraries(test_discovery OpenSSL::Crypto ws2_32)
add_test(NAME test_discovery COMMAND test_discovery)

add_executable(test_config test_config.cpp ../src/config/config.cpp)
target_include_directories(test_config PRIVATE ../include)
add_test(NAME test_config COMMAND test_config)

add_executable(test_invite test_invite.cpp ../src/invite/invite.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp)
target_include_directories(test_invite PRIVATE ../include)
target_link_libraries(test_invite OpenSSL::Crypto ws2_32)
add_test(NAME test_invite COMMAND test_invite)

add_executable(test_stun test_stun.cpp ../src/stun/stun.cpp ../src/platform/platform.cpp)
target_include_directories(test_stun PRIVATE ../include)
target_link_libraries(test_stun ws2_32)
add_test(NAME test_stun COMMAND test_stun)

add_executable(test_cli test_cli.cpp ../src/cli/input_parser.cpp ../src/cli/command_registry.cpp ../src/cli/commands.cpp ../src/cli/identity_store.cpp ../src/identity/identity.cpp ../src/crypto/x25519.cpp ../src/crypto/chacha20poly1305.cpp ../src/config/config.cpp ../src/invite/invite.cpp ../src/platform/platform.cpp ../src/platform/logger.cpp ../src/tunnel/tunnel.cpp ../src/peer/peer.cpp ../src/peer/peer_table.cpp ../src/session/session.cpp ../src/adapter/adapter.cpp ../src/packet/packet.cpp ../src/packet/relay.cpp ../src/routing/routing.cpp ../src/transport/transport.cpp ../src/discovery/discovery.cpp ../src/stun/stun.cpp)
target_include_directories(test_cli PRIVATE ../include)
target_link_libraries(test_cli OpenSSL::Crypto ws2_32 wintun iphlpapi)
add_test(NAME test_cli COMMAND test_cli)

add_custom_target(check
    COMMAND test_packet
    COMMAND test_transport
    COMMAND test_crypto
    COMMAND test_aead
    COMMAND test_identity
    COMMAND test_tunnel
    COMMAND test_session
    COMMAND test_peer
    COMMAND test_routing
    COMMAND test_peer_table
    COMMAND test_relay
    COMMAND test_discovery
    COMMAND test_config
    COMMAND test_invite
    COMMAND test_stun
    COMMAND test_cli
    COMMENT "Running all unit tests"
)

