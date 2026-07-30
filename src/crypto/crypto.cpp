#include "aegis/crypto/crypto.hpp"
#include <cstdio>

#ifdef AEGIS_USE_LIBSODIUM
#include <sodium.h>
#endif

bool Crypto::generate_keypair(Key& private_key, Key& public_key) {
#ifdef AEGIS_USE_LIBSODIUM
    if (sodium_init() < 0) return false;
    return crypto_box_keypair(public_key.data(), private_key.data()) == 0;
#else
    (void)private_key;
    (void)public_key;
    fprintf(stderr, "[crypto] generate_keypair: crypto library not configured\n");
    return false;
#endif
}

Key Crypto::derive_shared_secret(
    const Key& private_key, const Key& peer_public_key
) {
    Key secret{};
#ifdef AEGIS_USE_LIBSODIUM
    if (crypto_scalarmult(secret.data(), private_key.data(), peer_public_key.data()) != 0) {
        fprintf(stderr, "[crypto] derive_shared_secret: failed\n");
    }
#else
    (void)private_key;
    (void)peer_public_key;
    fprintf(stderr, "[crypto] derive_shared_secret: crypto library not configured\n");
#endif
    return secret;
}

std::vector<uint8_t> Crypto::derive_session_key(
    const Key& shared_secret, uint32_t session_id
) {
    (void)shared_secret;
    (void)session_id;
    fprintf(stderr, "[crypto] derive_session_key: not implemented\n");
    return {};
}

bool Crypto::encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& tag
) {
    (void)key; (void)nonce; (void)plaintext; (void)aad;
    (void)ciphertext; (void)tag;
    fprintf(stderr, "[crypto] encrypt: not implemented\n");
    return false;
}

bool Crypto::decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& tag,
    std::vector<uint8_t>& plaintext
) {
    (void)key; (void)nonce; (void)ciphertext; (void)aad;
    (void)tag; (void)plaintext;
    fprintf(stderr, "[crypto] decrypt: not implemented\n");
    return false;
}

NodeId Crypto::hash_to_node_id(const Key& public_key) {
    NodeId id{};
#ifdef AEGIS_USE_LIBSODIUM
    crypto_generichash(id.data(), id.size(),
                       public_key.data(), public_key.size(),
                       nullptr, 0);
#else
    (void)public_key;
    fprintf(stderr, "[crypto] hash_to_node_id: crypto library not configured\n");
#endif
    return id;
}
