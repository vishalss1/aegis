#include "aegis/identity/identity.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>

NodeId hash_public_key(const X25519Key& public_key) {
    NodeId hash{};
    unsigned char full_hash[64]{};
    unsigned int len = 64;
    if (EVP_Digest(public_key.data(), X25519_KEY_SIZE,
                   full_hash, &len, EVP_blake2b512(), nullptr) != 1) {
        fprintf(stderr, "[identity] EVP_Digest failed\n");
    }
    std::memcpy(hash.data(), full_hash, NODE_ID_SIZE);
    return hash;
}

Identity Identity::create(const NetworkId& network_id) {
    Identity id;
    id.keypair = x25519_generate_keypair();
    id.node_id = hash_public_key(id.keypair.public_key);
    id.network_id = network_id;
    return id;
}

bool Identity::matches_network(const NetworkId& other) const {
    return network_id == other;
}
