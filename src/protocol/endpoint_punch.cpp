#include "aegis/protocol/endpoint_punch.hpp"
#include "aegis/protocol/wire.hpp"

std::optional<std::vector<uint8_t>> serialize_endpoint_punch(
    const EndpointPunchMessage& message) {
    const auto kind = static_cast<uint8_t>(message.kind);
    if ((kind != static_cast<uint8_t>(EndpointPunchKind::Challenge) &&
         kind != static_cast<uint8_t>(EndpointPunchKind::Response)) ||
        message.transaction_id == 0)
        return std::nullopt;
    std::vector<uint8_t> payload(ENDPOINT_PUNCH_WIRE_SIZE);
    WireWriter writer(payload);
    if (!writer.write_u8(1) || !writer.write_u8(kind) ||
        !writer.write_u16(0) || !writer.write_u64(message.transaction_id) ||
        !writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<EndpointPunchMessage> deserialize_endpoint_punch(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto version = reader.read_u8();
    const auto kind = reader.read_u8();
    const auto reserved = reader.read_u16();
    const auto transaction_id = reader.read_u64();
    if (!version || !kind || !reserved || !transaction_id ||
        !reader.finished() || *version != 1 || *reserved != 0 ||
        (*kind != static_cast<uint8_t>(EndpointPunchKind::Challenge) &&
         *kind != static_cast<uint8_t>(EndpointPunchKind::Response)) ||
        *transaction_id == 0)
        return std::nullopt;
    return EndpointPunchMessage{
        static_cast<EndpointPunchKind>(*kind), *transaction_id};
}

EndpointPunchTracker::EndpointPunchTracker(
    size_t maximum, std::chrono::steady_clock::duration timeout)
    : maximum_(maximum), timeout_(timeout) {}

bool EndpointPunchTracker::begin(
    uint64_t transaction_id, const EndpointPunchTarget& target,
    ProtocolClock::time_point now) {
    if (transaction_id == 0 || target.peer_id == NodeId{} ||
        !valid_endpoint_candidate({EndpointCandidateType::PeerObserved,
                                   target.endpoint, 1}) ||
        maximum_ == 0 || timeout_ <=
            std::chrono::steady_clock::duration::zero())
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.size() >= maximum_ || pending_.contains(transaction_id))
        return false;
    for (const auto& [unused, pending] : pending_) {
        (void)unused;
        if (pending.target == target)
            return false;
    }
    pending_.emplace(transaction_id, Pending{target, now});
    return true;
}

std::optional<EndpointPunchTarget> EndpointPunchTracker::acknowledge(
    uint64_t transaction_id, const NodeId& peer_id,
    Endpoint source, ProtocolClock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = pending_.find(transaction_id);
    if (it == pending_.end() || it->second.target.peer_id != peer_id ||
        !(it->second.target.endpoint == source) ||
        now < it->second.sent_at || now - it->second.sent_at >= timeout_)
        return std::nullopt;
    auto target = it->second.target;
    pending_.erase(it);
    return target;
}

std::vector<uint64_t> EndpointPunchTracker::expire(
    ProtocolClock::time_point now) {
    std::vector<uint64_t> expired;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now >= it->second.sent_at &&
            now - it->second.sent_at >= timeout_) {
            expired.push_back(it->first);
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

void EndpointPunchTracker::cancel(uint64_t transaction_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.erase(transaction_id);
}

void EndpointPunchTracker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.clear();
}

size_t EndpointPunchTracker::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.size();
}
