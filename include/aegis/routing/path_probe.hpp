#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

inline constexpr size_t PATH_PROBE_WIRE_SIZE = 20;
inline constexpr size_t PATH_PROBE_MAX_PENDING = 256;
inline constexpr std::chrono::seconds PATH_PROBE_INTERVAL{30};
inline constexpr std::chrono::seconds PATH_PROBE_TIMEOUT{5};

enum class PathProbeKind : uint8_t {
    Challenge = 1,
    Response = 2
};

struct PathProbeMessage {
    PathProbeKind kind = PathProbeKind::Challenge;
    uint64_t probe_id = 0;
    uint64_t route_sequence = 0;
};

[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_path_probe(
    const PathProbeMessage& probe);
[[nodiscard]] std::optional<PathProbeMessage> deserialize_path_probe(
    std::span<const uint8_t> payload);

struct PathProbeTarget {
    NodeId destination{};
    NodeId next_hop{};
    uint32_t prefix = 0;
    uint32_t prefix_length = 0;
    uint64_t route_sequence = 0;

    [[nodiscard]] bool operator==(const PathProbeTarget&) const = default;
};

struct PathProbeObservation {
    PathProbeTarget target;
    std::chrono::steady_clock::duration rtt{};
};

class PathProbeTracker {
public:
    explicit PathProbeTracker(
        size_t maximum = PATH_PROBE_MAX_PENDING,
        std::chrono::steady_clock::duration timeout = PATH_PROBE_TIMEOUT);

    [[nodiscard]] bool begin(
        uint64_t probe_id, const PathProbeTarget& target,
        ProtocolClock::time_point now);
    [[nodiscard]] std::optional<PathProbeObservation> acknowledge(
        uint64_t probe_id, const NodeId& responder,
        uint64_t route_sequence, ProtocolClock::time_point now);
    [[nodiscard]] std::vector<PathProbeTarget> expire(
        ProtocolClock::time_point now);
    [[nodiscard]] bool contains_target(const PathProbeTarget& target) const;
    void cancel(uint64_t probe_id);
    void reset();
    [[nodiscard]] size_t size() const;

private:
    struct Pending {
        PathProbeTarget target;
        ProtocolClock::time_point sent_at{};
    };

    size_t maximum_;
    std::chrono::steady_clock::duration timeout_;
    mutable std::mutex mutex_;
    std::map<uint64_t, Pending> pending_;
};
