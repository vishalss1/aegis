#pragma once

#include "aegis/crypto/x25519.hpp"
#include <array>
#include <cstdint>
#include <optional>

static constexpr size_t KEY_SIZE = 32;
static constexpr size_t IDENTITY_SIGNATURE_SIZE = 64;
static constexpr size_t NODE_ID_SIZE = 32;
static constexpr size_t NETWORK_ID_SIZE = 32;

using Key = std::array<uint8_t, KEY_SIZE>;
using IdentitySignature = std::array<uint8_t, IDENTITY_SIGNATURE_SIZE>;
using NodeId = std::array<uint8_t, NODE_ID_SIZE>;
using NetworkId = std::array<uint8_t, NETWORK_ID_SIZE>;

struct SigningKeyPair {
    Key public_key{};
    Key private_key{};
};

NodeId hash_public_key(const X25519Key& public_key);

struct Identity {
    // Ed25519 signing identity is cryptographically separate from the
    // rotatable X25519 key used by Noise IK.
    SigningKeyPair signing_keypair{};
    X25519KeyPair keypair{};
    IdentitySignature key_agreement_binding{};
    NodeId node_id{};
    NetworkId network_id{};
    NodeId creator_node_id{};

    static Identity create(const NetworkId& network_id);

    bool matches_network(const NetworkId& other) const;
};

struct IdentityRotationCertificate {
    Key previous_signing_public_key{};
    X25519Key previous_key_agreement_public_key{};
    IdentitySignature previous_key_agreement_binding{};
    Key next_signing_public_key{};
    X25519Key next_key_agreement_public_key{};
    IdentitySignature next_key_agreement_binding{};
    uint64_t issued_at = 0;
    IdentitySignature rotation_signature{};
};

// Recreate a signing identity and binding around an existing legacy X25519
// key. Credential persistence is versioned in the following migration step.
[[nodiscard]] bool bind_identity_keys(Identity& identity);
[[nodiscard]] bool bind_identity_keys(
    Identity& identity, const Key& signing_private_key);
[[nodiscard]] bool verify_key_agreement_binding(
    const Identity& identity);
[[nodiscard]] std::optional<IdentityRotationCertificate>
create_identity_rotation_certificate(
    const Identity& previous_identity, const Identity& next_identity,
    uint64_t issued_at);
// The expected previous signing key is the trust anchor; the certificate's
// embedded key alone must never be treated as authorization.
[[nodiscard]] bool verify_identity_rotation_certificate(
    const IdentityRotationCertificate& certificate,
    const Key& expected_previous_signing_public_key);
