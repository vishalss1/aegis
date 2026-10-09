#pragma once

#include "aegis/transport/transport.hpp"
#include "aegis/crypto/random.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Formats a 20-byte RFC 5389 STUN Binding Request header.
std::vector<uint8_t> create_stun_binding_request(const uint8_t transaction_id[12]);

// Parses an RFC 5389 STUN Binding Response and extracts XOR-MAPPED-ADDRESS
// (IPv4 or IPv6; IPv6 is XORed with the cookie and transaction ID).
std::optional<Endpoint> parse_stun_binding_response(
    const uint8_t* data, size_t len, const uint8_t expected_tx_id[12]);

// Sends a Binding Request through an already-bound transport socket and
// returns the public endpoint observed for that same socket. The server is
// resolved to the address families the socket can reach; `family` restricts
// that further (e.g. IPv4 where the consumer cannot yet carry IPv6).
std::optional<Endpoint> stun_discover(
    Transport& transport, const std::string& stun_host, uint16_t stun_port,
    int timeout_ms = 2000,
    RandomSource& random = system_random_source(),
    std::optional<IPAddressFamily> family = std::nullopt);
