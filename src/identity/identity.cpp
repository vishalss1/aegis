#include "aegis/identity/identity.hpp"
#include <openssl/evp.h>
#include <cstdio>

NodeId hash_public_key(const X25519Key& public_key) {
    NodeId hash{};
    unsigned int len = NODE_ID_SIZE;
    if (EVP_Digest(public_key.data(), X25519_KEY_SIZE,
                   hash.data(), &len, EVP_sha256(), nullptr) != 1) {
        fprintf(stderr, "[identity] EVP_Digest failed\n");
    }
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
