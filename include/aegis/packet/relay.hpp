#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/chacha20poly1305.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Step 13: relay / onion routing. A source routes an IP packet to a
// non-adjacent destination through a chain of intermediate relays by wrapping
// it in one AEAD layer per hop. Each layer is keyed with a static shared
// secret between the source and that hop:
//
//     layer_key(H) = SHA256("aegis-onion-v1" || X25519(S_priv, H_pub))
//
// so the source can build the whole onion from public keys it learned via
// peer-table gossip, and each relay can open exactly its own layer — revealing
// only the next hop, never the final payload or the full path.
//
// Blob layout (opaque to every hop except its owner):
//     [12] nonce
//     [var] AEAD(layer_key, nonce, next_hop(32) || inner)
// where next_hop is the next hop's NodeID, or all-zero for the final
// destination (whose `inner` is the original IP packet). The source NodeID is
// prepended outside the onion (in the TYPE_RELAY frame payload) so every relay
// knows which public key to peel with.

static constexpr size_t ONION_NEXT_HOP_SIZE = NODE_ID_SIZE;
static constexpr size_t ONION_NONCE_SIZE    = CHACHA20_POLY1305_NONCE_SIZE;
static constexpr size_t ONION_TAG_SIZE      = CHACHA20_POLY1305_TAG_SIZE;
static constexpr size_t ONION_OVERHEAD =
    ONION_NONCE_SIZE + ONION_TAG_SIZE + ONION_NEXT_HOP_SIZE;
static constexpr size_t ONION_MAX_HOPS = 8;

// Wrap `packet` in one layer per hop of `path`. `path_pubkeys` must hold the
// public key of every hop, in the same order as `path`. Returns the outermost
// blob, which the caller delivers (inside a TYPE_RELAY frame) to path[0].
std::optional<std::vector<uint8_t>> build_onion(
    const X25519KeyPair& self,
    const std::vector<NodeId>& path,
    const std::vector<Key>& path_pubkeys,
    const uint8_t* packet, size_t packet_len);

struct PeeledOnion {
    NodeId next_hop{};           // all-zero => this node is the destination
    std::vector<uint8_t> inner;  // next layer blob, or the IP packet if final
};

// Open one onion layer from `blob`, using our static key and the source's
// public key. Fails if the layer was not written for us (wrong source, or a
// tampered onion).
std::optional<PeeledOnion> peel_onion(
    const X25519KeyPair& self,
    const Key& source_public_key,
    const uint8_t* blob, size_t blob_len);
