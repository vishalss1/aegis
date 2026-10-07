#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

inline constexpr uint8_t ENDPOINT_CANDIDATE_VERSION = 1;
inline constexpr size_t ENDPOINT_CANDIDATE_MAX_COUNT = 8;
inline constexpr size_t ENDPOINT_CANDIDATE_HEADER_SIZE = 36;
inline constexpr size_t ENDPOINT_CANDIDATE_ENTRY_SIZE = 12;

enum class EndpointCandidateType : uint8_t {
    Host = 1,
    ServerReflexive = 2,
    PeerObserved = 3
};

struct EndpointCandidate {
    EndpointCandidateType type = EndpointCandidateType::Host;
    Endpoint endpoint{};
    uint32_t priority = 0;

    [[nodiscard]] bool operator==(const EndpointCandidate&) const = default;
};

struct EndpointCandidateMessage {
    NodeId subject{};
    std::vector<EndpointCandidate> candidates;
};

[[nodiscard]] bool valid_endpoint_candidate(
    const EndpointCandidate& candidate) noexcept;
[[nodiscard]] std::optional<std::vector<uint8_t>>
serialize_endpoint_candidates(const EndpointCandidateMessage& message);
[[nodiscard]] std::optional<EndpointCandidateMessage>
deserialize_endpoint_candidates(std::span<const uint8_t> payload);

// Enumerates bounded local IPv4 host candidates for the bound mesh port.
[[nodiscard]] std::vector<EndpointCandidate> gather_host_candidates(
    uint16_t local_port);
