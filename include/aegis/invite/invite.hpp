#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct InvitePayload {
    NetworkId   network_id{};          // 32 bytes
    Key         bootstrap_pubkey{};    // 32 bytes
    NodeId      creator_node_id{};     // 32 bytes
    Endpoint    bootstrap_endpoint{};  // 6 bytes (4-byte IP, 2-byte port)
    uint32_t    bootstrap_prefix = 0;  // 4 bytes
    uint8_t     bootstrap_prefix_len = 0; // 1 byte
    std::string network_name;          // variable length (up to 64 bytes)
};

std::string encode_invite(const InvitePayload& payload);
std::optional<InvitePayload> decode_invite(const std::string& invite_str);

// AEGIS2 is a signed membership grant. Its enrollment nonce identifies the
// intended enrollment without exposing or requiring a subject key in the
// invite itself. Time and capability policy is enforced by a later layer.
struct Aegis2PrefixGrant {
    uint32_t prefix = 0;
    uint8_t prefix_len = 0;
};

struct Aegis2BootstrapCandidate {
    Key x25519_public_key{};
    Endpoint endpoint{};
};

struct Aegis2MembershipGrant {
    NetworkId network_id{};
    Key issuer_signing_public_key{};
    NodeId issuer_node_id{};
    Key enrollment_nonce{};
    uint64_t issued_at = 0;
    uint64_t expires_at = 0;
    uint64_t capabilities = 0;
    uint64_t revocation_epoch = 0;
    std::vector<Aegis2PrefixGrant> allowed_prefixes;
    std::vector<Aegis2BootstrapCandidate> bootstrap_candidates;
    IdentitySignature signature{};
};

inline constexpr size_t AEGIS2_MAX_PREFIXES = 16;
inline constexpr size_t AEGIS2_MAX_BOOTSTRAP_CANDIDATES = 4;

// The signer private key must correspond to issuer_signing_public_key.
[[nodiscard]] std::string encode_aegis2_grant(
    const Aegis2MembershipGrant& grant, const Key& issuer_signing_private_key);
// Decoding verifies the embedded Ed25519 signature, but does not establish
// that the issuer is trusted; callers must pin/authorize the issuer key.
[[nodiscard]] std::optional<Aegis2MembershipGrant> decode_aegis2_grant(
    const std::string& invite_str);
[[nodiscard]] bool verify_aegis2_grant_signature(
    const Aegis2MembershipGrant& grant);
