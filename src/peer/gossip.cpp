#include "aegis/peer/gossip.hpp"
#include <algorithm>
#include <limits>

namespace {
bool same_advertisement(
    const AdvertisedPeer& left, const AdvertisedPeer& right) {
    return left.node_id == right.node_id &&
           left.public_key == right.public_key &&
           left.path == right.path &&
           left.prefixes == right.prefixes;
}

AdvertisedPeer canonicalize(AdvertisedPeer peer) {
    std::sort(peer.prefixes.begin(), peer.prefixes.end());
    peer.prefixes.erase(
        std::unique(peer.prefixes.begin(), peer.prefixes.end()),
        peer.prefixes.end());
    return peer;
}
} // namespace

std::vector<GossipUpdate> GossipDeltaTracker::prepare(
    const NodeId& recipient,
    const std::vector<AdvertisedPeer>& current,
    bool force_full) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::map<NodeId, AdvertisedPeer> canonical;
    for (auto peer : current)
        canonical[peer.node_id] = canonicalize(std::move(peer));

    for (auto state = current_.begin(); state != current_.end();) {
        if (!canonical.contains(state->first))
            state = current_.erase(state);
        else
            ++state;
    }
    for (auto& [node_id, peer] : canonical) {
        auto state = current_.find(node_id);
        if (state == current_.end() ||
            !same_advertisement(state->second.peer, peer)) {
            CurrentAdvertisement replacement;
            replacement.peer = std::move(peer);
            replacement.revision = next_revision_++;
            current_[node_id] = std::move(replacement);
        }
    }

    for (auto& [unused_recipient, revisions] : sent_) {
        (void)unused_recipient;
        for (auto revision = revisions.begin(); revision != revisions.end();) {
            if (!current_.contains(revision->first))
                revision = revisions.erase(revision);
            else
                ++revision;
        }
    }

    std::vector<GossipUpdate> updates;
    const auto sent = sent_.find(recipient);
    for (const auto& [node_id, state] : current_) {
        bool already_sent = false;
        if (sent != sent_.end()) {
            const auto revision = sent->second.find(node_id);
            already_sent = revision != sent->second.end() &&
                           revision->second == state.revision;
        }
        if (force_full || !already_sent)
            updates.push_back({state.peer, state.revision});
    }
    return updates;
}

void GossipDeltaTracker::commit(
    const NodeId& recipient,
    const std::vector<std::pair<NodeId, uint64_t>>& revisions) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& recipient_revisions = sent_[recipient];
    for (const auto& [node_id, revision] : revisions) {
        auto& committed = recipient_revisions[node_id];
        committed = (std::max)(committed, revision);
    }
}

void GossipDeltaTracker::retain_recipients(
    const std::set<NodeId>& recipients) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto recipient = sent_.begin(); recipient != sent_.end();) {
        if (!recipients.contains(recipient->first))
            recipient = sent_.erase(recipient);
        else
            ++recipient;
    }
}

void GossipDeltaTracker::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    current_.clear();
    sent_.clear();
    next_revision_ = 1;
}

size_t GossipDeltaTracker::recipient_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sent_.size();
}

std::vector<GossipBatch> make_gossip_batches(
    const std::vector<GossipUpdate>& updates,
    size_t max_payload_bytes) {
    std::vector<GossipBatch> batches;
    max_payload_bytes = (std::min)(
        max_payload_bytes, PEER_TABLE_MAX_WIRE_BYTES);
    if (max_payload_bytes < 3)
        return batches;
    GossipBatch current;

    auto flush = [&]() {
        if (!current.peers.empty()) {
            batches.push_back(std::move(current));
            current = {};
        }
    };

    for (const auto& update : updates) {
        if (update.peer.path.size() > PEER_TABLE_MAX_PATH_HOPS)
            continue;

        const size_t prefix_count = update.peer.prefixes.size();
        const size_t part_count = (std::max)(
            size_t{1},
            (prefix_count + PEER_TABLE_MAX_PREFIXES - 1) /
                PEER_TABLE_MAX_PREFIXES);
        std::vector<AdvertisedPeer> chunks;
        chunks.reserve(part_count);
        bool logical_peer_fits = true;
        for (size_t part = 0; part < part_count; ++part) {
            AdvertisedPeer chunk = update.peer;
            const size_t begin = part * PEER_TABLE_MAX_PREFIXES;
            const size_t end = (std::min)(
                prefix_count, begin + PEER_TABLE_MAX_PREFIXES);
            if (begin < end) {
                chunk.prefixes.assign(
                    update.peer.prefixes.begin() +
                        static_cast<std::vector<AdvertisedPrefix>::difference_type>(begin),
                    update.peer.prefixes.begin() +
                        static_cast<std::vector<AdvertisedPrefix>::difference_type>(end));
            } else {
                chunk.prefixes.clear();
            }

            const auto single = serialize_peer_table({chunk});
            if (!single || single->size() > max_payload_bytes) {
                logical_peer_fits = false;
                break;
            }
            chunks.push_back(std::move(chunk));
        }
        if (!logical_peer_fits)
            continue;

        for (size_t part = 0; part < chunks.size(); ++part) {
            auto& chunk = chunks[part];
            auto candidate = current.peers;
            candidate.push_back(chunk);
            auto encoded = serialize_peer_table(candidate);
            if (!encoded || encoded->size() > max_payload_bytes) {
                flush();
            }
            current.peers.push_back(std::move(chunk));
            if (part + 1 == chunks.size()) {
                current.completed_revisions.emplace_back(
                    update.peer.node_id, update.revision);
            }
        }
    }
    flush();
    return batches;
}

std::chrono::milliseconds jittered_gossip_interval(
    std::optional<uint64_t> sample,
    std::chrono::milliseconds base,
    std::chrono::milliseconds jitter) {
    if (!sample || base.count() <= 0 || jitter.count() < 0 ||
        jitter > base)
        return base;

    const uint64_t radius = static_cast<uint64_t>(jitter.count());
    if (radius > ((std::numeric_limits<uint64_t>::max)() - 1) / 2)
        return base;
    const uint64_t span = radius * 2 + 1;
    const int64_t offset = static_cast<int64_t>(*sample % span) -
                           static_cast<int64_t>(radius);
    return base + std::chrono::milliseconds(offset);
}
