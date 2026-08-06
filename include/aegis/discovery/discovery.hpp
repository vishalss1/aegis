#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/transport/transport.hpp"
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <atomic>
#include <vector>

// LAN-wide presence broadcast (step 14). Every node on the shared LAN — and
// every mesh's node on the LAN — announces NodeID + NetworkID + endpoint on a
// fixed discovery port. Discovery is deliberately network-agnostic: a node
// SEES every other node's presence regardless of NetworkID (the one accepted
// exception to the identity-hiding threat model — presence leaks, sessions do
// not). Whether a presence turns into a session is decided elsewhere, gated by
// the NetworkID at the Session Manager.
//
// Port choice: must sit below the ephemeral range AND outside the ranges
// Windows dynamically reserves for "Administered port exclusions" (49k+),
// which intermittently fail bind with WSAEACCES on some systems.
static constexpr uint16_t DISCOVERY_PORT = 45950;
static constexpr size_t DISCOVERY_PAYLOAD_SIZE = 102;  // NodeID+NetworkID+CreatorID+endpoint

// Presence wire format (cleartext, pre-session metadata):
//   [0:16]   PacketHeader (type = TYPE_DISCOVERY, payload_length = 102)
//   [16:48]  NodeID   (32)
//   [48:80]  NetworkID(32)
//   [80:112] CreatorID(32)
//   [112:116] endpoint IP   (4, network byte order)
//   [116:118] endpoint port (2, network byte order)
static constexpr size_t DISCOVERY_FRAME_SIZE = 16 + DISCOVERY_PAYLOAD_SIZE;

struct Presence {
    NodeId node_id{};
    NetworkId network_id{};
    NodeId creator_node_id{};
    Endpoint endpoint{};        // announced endpoint (overlay IP + listen port)
    Endpoint reachable_endpoint{};  // actual connect target: sender IP + announced listen port
    int64_t last_seen_ms = 0;
};

class Discovery {
public:
    Discovery() = default;
    ~Discovery();

    Discovery(const Discovery&) = delete;
    Discovery& operator=(const Discovery&) = delete;

    // Opens the discovery socket and starts the announce + listen loops.
    // `endpoint` is what this node advertises (overlay IP + listen port).
    bool start(const Identity& identity, const Endpoint& endpoint,
               uint16_t discovery_port = DISCOVERY_PORT);
    void stop();

    // Snapshot of every presence seen so far, indexed by NodeID (network-agnostic).
    std::map<NodeId, Presence> presences() const;

    static std::vector<uint8_t> build_presence(const Identity& identity,
                                               const Endpoint& endpoint);
    static std::optional<Presence> parse_presence(const uint8_t* data, size_t len);

private:
    const Identity* identity_ = nullptr;
    Endpoint announced_endpoint_{};
    uint16_t discovery_port_ = DISCOVERY_PORT;

    Transport socket_;
    std::thread announce_thread_;
    std::atomic<bool> running_{false};

    std::map<NodeId, Presence> presences_;
    mutable std::mutex mtx_;

    void announce_loop();
    void on_presence(const uint8_t* data, size_t len, Endpoint sender);
};
