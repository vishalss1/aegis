#pragma once

#include "aegis/protocol/endpoint_candidate.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

inline constexpr size_t ENDPOINT_PUNCH_WIRE_SIZE = 12;
inline constexpr size_t ENDPOINT_PUNCH_MAX_PENDING = 256;
inline constexpr std::chrono::seconds ENDPOINT_PUNCH_TIMEOUT{5};

enum class EndpointPunchKind : uint8_t {
    Challenge = 1,
    Response = 2
};

struct EndpointPunchMessage {
    EndpointPunchKind kind = EndpointPunchKind::Challenge;
    uint64_t transaction_id = 0;
};

struct EndpointPunchTarget {
    NodeId peer_id{};
    Endpoint endpoint{};

    [[nodiscard]] bool operator==(const EndpointPunchTarget&) const = default;
};

[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_endpoint_punch(
    const EndpointPunchMessage& message);
[[nodiscard]] std::optional<EndpointPunchMessage> deserialize_endpoint_punch(
    std::span<const uint8_t> payload);

class EndpointPunchTracker {
public:
    explicit EndpointPunchTracker(
        size_t maximum = ENDPOINT_PUNCH_MAX_PENDING,
        std::chrono::steady_clock::duration timeout =
            ENDPOINT_PUNCH_TIMEOUT);

    [[nodiscard]] bool begin(
        uint64_t transaction_id, const EndpointPunchTarget& target,
        ProtocolClock::time_point now);
    [[nodiscard]] std::optional<EndpointPunchTarget> acknowledge(
        uint64_t transaction_id, const NodeId& peer_id,
        Endpoint source, ProtocolClock::time_point now);
    [[nodiscard]] std::vector<uint64_t> expire(
        ProtocolClock::time_point now);
    void cancel(uint64_t transaction_id);
    void reset();
    [[nodiscard]] size_t size() const;

private:
    struct Pending {
        EndpointPunchTarget target;
        ProtocolClock::time_point sent_at{};
    };

    size_t maximum_;
    std::chrono::steady_clock::duration timeout_;
    mutable std::mutex mutex_;
    std::map<uint64_t, Pending> pending_;
};
