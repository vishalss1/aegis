#pragma once

#include "aegis/identity/identity.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

// Handshake v2 carries Noise IK messages in a dedicated, bounded envelope:
//   version(1) || type(1) || flags(1) || session_id(4) ||
//   payload_length(2) || payload
//
// Noise_IK_25519_ChaChaPoly_BLAKE2s with an empty application payload has a
// 96-byte first message and a 48-byte second message. INIT prefixes the first
// Noise message with the cleartext 32-byte NetworkID routing selector.
static constexpr uint8_t HANDSHAKE_V2_VERSION = 0x02;
static constexpr uint8_t HANDSHAKE_V2_INIT_TYPE = 0x00;
static constexpr uint8_t HANDSHAKE_V2_RESPONSE_TYPE = 0x01;
static constexpr uint8_t HANDSHAKE_V2_FLAGS = 0x00;
static constexpr uint8_t HANDSHAKE_V2_INITIATOR_ROLE = 0x01;
static constexpr uint8_t HANDSHAKE_V2_RESPONDER_ROLE = 0x02;

inline constexpr std::string_view HANDSHAKE_V2_PROLOGUE_DOMAIN =
    "aegis-handshake-v2";
inline constexpr std::string_view HANDSHAKE_V2_NOISE_PROTOCOL =
    "Noise_IK_25519_ChaChaPoly_BLAKE2s";

static constexpr size_t HANDSHAKE_V2_HEADER_SIZE = 9;
static constexpr size_t HANDSHAKE_V2_INIT_NOISE_SIZE = 96;
static constexpr size_t HANDSHAKE_V2_RESPONSE_NOISE_SIZE = 48;
static constexpr size_t HANDSHAKE_V2_INIT_PAYLOAD_SIZE =
    NETWORK_ID_SIZE + HANDSHAKE_V2_INIT_NOISE_SIZE;
static constexpr size_t HANDSHAKE_V2_RESPONSE_PAYLOAD_SIZE =
    HANDSHAKE_V2_RESPONSE_NOISE_SIZE;
static constexpr size_t HANDSHAKE_V2_INIT_FRAME_SIZE =
    HANDSHAKE_V2_HEADER_SIZE + HANDSHAKE_V2_INIT_PAYLOAD_SIZE;
static constexpr size_t HANDSHAKE_V2_RESPONSE_FRAME_SIZE =
    HANDSHAKE_V2_HEADER_SIZE + HANDSHAKE_V2_RESPONSE_PAYLOAD_SIZE;
static constexpr size_t HANDSHAKE_V2_PROLOGUE_SIZE =
    1 + HANDSHAKE_V2_PROLOGUE_DOMAIN.size() +
    1 + HANDSHAKE_V2_NOISE_PROTOCOL.size() +
    1 + NETWORK_ID_SIZE + 4 + 2 +
    (2 * HANDSHAKE_V2_HEADER_SIZE);
static_assert(HANDSHAKE_V2_INIT_PAYLOAD_SIZE <= UINT16_MAX);
static_assert(HANDSHAKE_V2_RESPONSE_PAYLOAD_SIZE <= UINT16_MAX);

using HandshakeV2InitNoise =
    std::array<uint8_t, HANDSHAKE_V2_INIT_NOISE_SIZE>;
using HandshakeV2ResponseNoise =
    std::array<uint8_t, HANDSHAKE_V2_RESPONSE_NOISE_SIZE>;
using HandshakeV2Prologue =
    std::array<uint8_t, HANDSHAKE_V2_PROLOGUE_SIZE>;

struct HandshakeV2InitFrame {
    uint32_t session_id = 0;
    NetworkId network_id{};
    HandshakeV2InitNoise noise_message{};
};

struct HandshakeV2ResponseFrame {
    uint32_t session_id = 0;
    HandshakeV2ResponseNoise noise_message{};
};

// Canonical Noise prologue:
//   domain_len(1) || domain || noise_name_len(1) || noise_name ||
//   wire_version(1) || network_id(32) || session_id(4) ||
//   initiator_role(1) || responder_role(1) || init_header(9) ||
//   response_header(9)
//
// Both headers contain their canonical version, type, flags, session ID, and
// payload length. Integers use network byte order. This binds every outer
// dispatch field to the authenticated Noise transcript before either message
// is processed.
[[nodiscard]] std::optional<HandshakeV2Prologue>
make_handshake_v2_prologue(const NetworkId& network_id, uint32_t session_id);

[[nodiscard]] std::optional<
    std::array<uint8_t, HANDSHAKE_V2_INIT_FRAME_SIZE>>
serialize_handshake_v2_init(const HandshakeV2InitFrame& frame);

[[nodiscard]] std::optional<HandshakeV2InitFrame> parse_handshake_v2_init(
    std::span<const uint8_t> bytes);

[[nodiscard]] std::optional<
    std::array<uint8_t, HANDSHAKE_V2_RESPONSE_FRAME_SIZE>>
serialize_handshake_v2_response(const HandshakeV2ResponseFrame& frame);

[[nodiscard]] std::optional<HandshakeV2ResponseFrame>
parse_handshake_v2_response(std::span<const uint8_t> bytes);
