#include "aegis/identity.hpp"
#include "aegis/crypto.hpp"
#include <cstdio>
#include <algorithm>
#include <fstream>

Identity::Identity() = default;

bool Identity::generate() {
    if (!Crypto::generate_keypair(private_key_, public_key_))
        return false;
    derive_node_id();
    return true;
}

bool Identity::load_from_file(const std::string& path) {
    (void)path;
    fprintf(stderr, "[identity] load_from_file: not implemented\n");
    return false;
}

bool Identity::save_to_file(const std::string& path) const {
    (void)path;
    fprintf(stderr, "[identity] save_to_file: not implemented\n");
    return false;
}

void Identity::derive_node_id() {
    node_id_ = Crypto::hash_to_node_id(public_key_);
}
