#pragma once

#include "aegis/identity/identity.hpp"
#include <cstddef>
#include <mutex>
#include <optional>
#include <vector>

struct MembershipRevocation {
    NetworkId network_id{};
    Key issuer_signing_public_key{};
    Key enrollment_nonce{};
    uint64_t revocation_epoch = 0;
    uint64_t issued_at = 0;
    IdentitySignature signature{};
};

inline constexpr size_t MEMBERSHIP_REVOCATION_MAX_RECORDS = 16;
inline constexpr size_t MEMBERSHIP_REVOCATION_MAX_STORED = 1024;
inline constexpr size_t MEMBERSHIP_REVOCATION_RECORD_SIZE = 176;

[[nodiscard]] std::optional<MembershipRevocation> sign_membership_revocation(
    const NetworkId& network_id, const Key& issuer_signing_public_key,
    const Key& issuer_signing_private_key, const Key& enrollment_nonce,
    uint64_t revocation_epoch, uint64_t issued_at);
[[nodiscard]] bool verify_membership_revocation(
    const MembershipRevocation& revocation);
[[nodiscard]] std::optional<std::vector<uint8_t>>
serialize_membership_revocations(
    const std::vector<MembershipRevocation>& revocations);
[[nodiscard]] std::optional<std::vector<MembershipRevocation>>
deserialize_membership_revocations(const uint8_t* data, size_t length);

// Stores the highest epoch for each (issuer, enrollment nonce) pair. Storage
// is bounded; rejected records never evict previously accepted revocations.
class MembershipRevocationStore {
public:
    [[nodiscard]] bool add(const MembershipRevocation& revocation);
    [[nodiscard]] std::vector<MembershipRevocation> snapshot() const;
    [[nodiscard]] size_t size() const;

private:
    mutable std::mutex mutex_;
    std::vector<MembershipRevocation> records_;
};
