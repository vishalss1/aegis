#include "aegis/packet/relay.hpp"
#include "aegis/crypto/x25519.hpp"
#include <openssl/evp.h>
#include <atomic>
#include <cstring>

namespace {

// Static layer key shared between the source and one hop:
//     SHA256("aegis-onion-v1" || X25519(our_priv, hop_pub))
// The same primitive the peer table is keyed on; a relay derives it with its
// own private key and the source's public key.
std::array<uint8_t, CHACHA20_POLY1305_KEY_SIZE> layer_key(
    const X25519Key& my_priv, const Key& hop_pub) {
    std::array<uint8_t, CHACHA20_POLY1305_KEY_SIZE> key{};
    auto shared = x25519_derive_shared_secret(my_priv, hop_pub);
    if (!shared) return key;

    const char label[] = "aegis-onion-v1";
    unsigned int out_len = (unsigned int)key.size();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, label, sizeof(label) - 1);
        EVP_DigestUpdate(ctx, shared->data(), shared->size());
        EVP_DigestFinal_ex(ctx, key.data(), &out_len);
        EVP_MD_CTX_free(ctx);
    }
    return key;
}

// Process-wide monotonic counter, mixed into every onion nonce. Each layer of
// each packet uses a different key (layer_key for a different hop), but the
// counter guarantees no (key, nonce) pair ever repeats even for repeated
// packets to the same hop.
std::atomic<uint64_t> g_onion_counter{0};

ChaCha20Poly1305Nonce make_nonce(uint32_t layer) {
    ChaCha20Poly1305Nonce n{};
    uint64_t c = g_onion_counter.fetch_add(1);
    for (int i = 0; i < 8; ++i)
        n[i] = (uint8_t)(c >> (i * 8));
    n[8]  = (uint8_t)(layer >> 24);
    n[9]  = (uint8_t)(layer >> 16);
    n[10] = (uint8_t)(layer >> 8);
    n[11] = (uint8_t)(layer);
    return n;
}

} // namespace

std::optional<std::vector<uint8_t>> build_onion(
    const X25519KeyPair& self,
    const std::vector<NodeId>& path,
    const std::vector<Key>& path_pubkeys,
    const uint8_t* packet, size_t packet_len) {
    if (path.empty() || path.size() != path_pubkeys.size() ||
        path.size() > ONION_MAX_HOPS)
        return std::nullopt;
    if (!packet || packet_len == 0)
        return std::nullopt;

    std::vector<uint8_t> inner(packet, packet + packet_len);

    // Wrap innermost (destination) layer first so the outermost layer belongs
    // to path[0].
    for (size_t i = path.size(); i-- > 0;) {
        NodeId next_hop{};
        if (i + 1 < path.size())
            next_hop = path[i + 1];

        std::vector<uint8_t> plaintext;
        plaintext.reserve(ONION_NEXT_HOP_SIZE + inner.size());
        plaintext.insert(plaintext.end(), next_hop.begin(), next_hop.end());
        plaintext.insert(plaintext.end(), inner.begin(), inner.end());

        auto key = layer_key(self.private_key, path_pubkeys[i]);
        auto nonce = make_nonce((uint32_t)i);

        std::vector<uint8_t> ct(plaintext.size());
        std::array<uint8_t, ONION_TAG_SIZE> tag{};
        if (!chacha20_poly1305_encrypt(key, nonce,
                plaintext.data(), plaintext.size(), ct.data(), tag.data())) {
            return std::nullopt;
        }

        std::vector<uint8_t> blob;
        blob.reserve(ONION_NONCE_SIZE + ct.size() + ONION_TAG_SIZE);
        blob.insert(blob.end(), nonce.begin(), nonce.end());
        blob.insert(blob.end(), ct.begin(), ct.end());
        blob.insert(blob.end(), tag.begin(), tag.end());
        inner = std::move(blob);
    }
    return inner;
}

std::optional<PeeledOnion> peel_onion(
    const X25519KeyPair& self,
    const Key& source_public_key,
    const uint8_t* blob, size_t blob_len) {
    if (!blob || blob_len < ONION_OVERHEAD)
        return std::nullopt;

    ChaCha20Poly1305Nonce nonce{};
    std::memcpy(nonce.data(), blob, ONION_NONCE_SIZE);
    size_t ct_len = blob_len - ONION_NONCE_SIZE - ONION_TAG_SIZE;
    const uint8_t* ct = blob + ONION_NONCE_SIZE;
    const uint8_t* tag = ct + ct_len;

    auto key = layer_key(self.private_key, source_public_key);

    PeeledOnion out;
    out.inner.resize(ct_len);
    if (!chacha20_poly1305_decrypt(key, nonce,
            ct, ct_len, tag, out.inner.data())) {
        return std::nullopt;
    }
    if (out.inner.size() < ONION_NEXT_HOP_SIZE)
        return std::nullopt;
    std::memcpy(out.next_hop.data(), out.inner.data(), ONION_NEXT_HOP_SIZE);
    out.inner.erase(out.inner.begin(), out.inner.begin() + ONION_NEXT_HOP_SIZE);
    return out;
}
