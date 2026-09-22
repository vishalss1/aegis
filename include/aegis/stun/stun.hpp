#pragma once

#include "aegis/transport/transport.hpp"
#include "aegis/crypto/random.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Formats a 20-byte RFC 5389 STUN Binding Request header.
std::vector<uint8_t> create_stun_binding_request(const uint8_t transaction_id[12]);

// Parses an RFC 5389 STUN Binding Response and extracts XOR-MAPPED-ADDRESS.
std::optional<Endpoint> parse_stun_binding_response(
    const uint8_t* data, size_t len, const uint8_t expected_tx_id[12]);

// Connects to a STUN server via UDP, sends a Binding Request, and returns the public Endpoint.
std::optional<Endpoint> stun_discover(
    const std::string& stun_host, uint16_t stun_port,
    uint16_t local_port = 0, int timeout_ms = 2000,
    RandomSource& random = system_random_source());
