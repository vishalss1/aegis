#pragma once

#include "identity.hpp"
#include <cstdint>
#include <vector>

class Crypto {
public:
    static bool generate_keypair(Key& private_key, Key& public_key);

    static Key derive_shared_secret(
        const Key& private_key,
        const Key& peer_public_key
    );

    static std::vector<uint8_t> derive_session_key(
        const Key& shared_secret,
        uint32_t session_id
    );

    static bool encrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    );

    static bool decrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& tag,
        std::vector<uint8_t>& plaintext
    );

    static NodeId hash_to_node_id(const Key& public_key);
};
