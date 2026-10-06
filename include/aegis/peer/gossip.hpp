#pragma once

#include "aegis/peer/peer_table.hpp"
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <utility>
#include <vector>

inline constexpr std::chrono::milliseconds GOSSIP_BASE_INTERVAL{3000};
inline constexpr std::chrono::milliseconds GOSSIP_JITTER{600};
inline constexpr size_t GOSSIP_FULL_RESYNC_ROUNDS = 10;

struct GossipUpdate {
    AdvertisedPeer peer;
    uint64_t revision = 0;
};

struct GossipBatch {
    std::vector<AdvertisedPeer> peers;
    // A logical peer is committed only in the batch containing its final
    // prefix chunk. Batches are sent in order and sending stops on failure.
    std::vector<std::pair<NodeId, uint64_t>> completed_revisions;
};

// Tracks the last logical advertisement accepted by each recipient's send
// queue. Revisions are assigned from exact field comparisons, not hashes.
class GossipDeltaTracker {
public:
    [[nodiscard]] std::vector<GossipUpdate> prepare(
        const NodeId& recipient,
        const std::vector<AdvertisedPeer>& current,
        bool force_full);
    void commit(const NodeId& recipient,
                const std::vector<std::pair<NodeId, uint64_t>>& revisions);
    void retain_recipients(const std::set<NodeId>& recipients);
    void reset();

    [[nodiscard]] size_t recipient_count() const;

private:
    struct CurrentAdvertisement {
        AdvertisedPeer peer;
        uint64_t revision = 0;
    };

    std::map<NodeId, CurrentAdvertisement> current_;
    std::map<NodeId, std::map<NodeId, uint64_t>> sent_;
    uint64_t next_revision_ = 1;
    mutable std::mutex mutex_;
};

// Splits a logical peer's prefixes into protocol-sized chunks, then greedily
// packs chunks into messages accepted by serialize_peer_table().
[[nodiscard]] std::vector<GossipBatch> make_gossip_batches(
    const std::vector<GossipUpdate>& updates,
    size_t max_payload_bytes = PEER_TABLE_MAX_WIRE_BYTES);

// Applies symmetric jitter. A missing sample falls back to the base interval.
[[nodiscard]] std::chrono::milliseconds jittered_gossip_interval(
    std::optional<uint64_t> sample,
    std::chrono::milliseconds base = GOSSIP_BASE_INTERVAL,
    std::chrono::milliseconds jitter = GOSSIP_JITTER);
