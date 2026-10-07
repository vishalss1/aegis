#include "aegis/routing/path_probe.hpp"
#include "aegis/protocol/wire.hpp"

std::optional<std::vector<uint8_t>> serialize_path_probe(
    const PathProbeMessage& probe) {
    const uint8_t kind = static_cast<uint8_t>(probe.kind);
    if ((kind != static_cast<uint8_t>(PathProbeKind::Challenge) &&
         kind != static_cast<uint8_t>(PathProbeKind::Response)) ||
        probe.probe_id == 0 || probe.route_sequence == 0)
        return std::nullopt;
    std::vector<uint8_t> payload(PATH_PROBE_WIRE_SIZE);
    WireWriter writer(payload);
    if (!writer.write_u8(1) || !writer.write_u8(kind) ||
        !writer.write_u16(0) || !writer.write_u64(probe.probe_id) ||
        !writer.write_u64(probe.route_sequence) || !writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<PathProbeMessage> deserialize_path_probe(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto version = reader.read_u8();
    const auto kind = reader.read_u8();
    const auto reserved = reader.read_u16();
    const auto probe_id = reader.read_u64();
    const auto route_sequence = reader.read_u64();
    if (!version || !kind || !reserved || !probe_id || !route_sequence ||
        !reader.finished() || *version != 1 || *reserved != 0 ||
        (*kind != static_cast<uint8_t>(PathProbeKind::Challenge) &&
         *kind != static_cast<uint8_t>(PathProbeKind::Response)) ||
        *probe_id == 0 || *route_sequence == 0)
        return std::nullopt;
    return PathProbeMessage{
        static_cast<PathProbeKind>(*kind), *probe_id, *route_sequence};
}

PathProbeTracker::PathProbeTracker(
    size_t maximum, std::chrono::steady_clock::duration timeout)
    : maximum_(maximum), timeout_(timeout) {}

bool PathProbeTracker::begin(
    uint64_t probe_id, const PathProbeTarget& target,
    ProtocolClock::time_point now) {
    if (probe_id == 0 || target.route_sequence == 0 || maximum_ == 0 ||
        timeout_ <= std::chrono::steady_clock::duration::zero())
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.size() >= maximum_ || pending_.contains(probe_id))
        return false;
    for (const auto& [unused, pending] : pending_) {
        (void)unused;
        if (pending.target == target)
            return false;
    }
    pending_.emplace(probe_id, Pending{target, now});
    return true;
}

std::optional<PathProbeObservation> PathProbeTracker::acknowledge(
    uint64_t probe_id, const NodeId& responder, uint64_t route_sequence,
    ProtocolClock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = pending_.find(probe_id);
    if (it == pending_.end() || it->second.target.destination != responder ||
        it->second.target.route_sequence != route_sequence ||
        now < it->second.sent_at || now - it->second.sent_at >= timeout_)
        return std::nullopt;
    PathProbeObservation observation{
        it->second.target, now - it->second.sent_at};
    pending_.erase(it);
    return observation;
}

std::vector<PathProbeTarget> PathProbeTracker::expire(
    ProtocolClock::time_point now) {
    std::vector<PathProbeTarget> expired;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now >= it->second.sent_at &&
            now - it->second.sent_at >= timeout_) {
            expired.push_back(it->second.target);
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

bool PathProbeTracker::contains_target(const PathProbeTarget& target) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [unused, pending] : pending_) {
        (void)unused;
        if (pending.target == target)
            return true;
    }
    return false;
}

void PathProbeTracker::cancel(uint64_t probe_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.erase(probe_id);
}

void PathProbeTracker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.clear();
}

size_t PathProbeTracker::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.size();
}
