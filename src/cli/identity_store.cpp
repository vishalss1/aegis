#include "aegis/cli/identity_store.hpp"
#include <openssl/evp.h>
#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <fstream>

std::string get_identity_file_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::string dir = std::string(path) + "\\Aegis";
        CreateDirectoryA(dir.c_str(), NULL);
        return dir + "\\identity.bin";
    }
    return "identity.bin";
}

Identity load_or_create_identity(const NetworkId& network_id, const std::string& custom_path) {
    std::string file_path = custom_path.empty() ? get_identity_file_path() : custom_path;

    std::ifstream in(file_path, std::ios::binary);
    if (in.is_open()) {
        X25519PrivateKey priv{};
        in.read(reinterpret_cast<char*>(priv.data()), priv.size());
        if (in.gcount() == static_cast<std::streamsize>(priv.size())) {
            Identity id;
            id.keypair.private_key = priv;

            EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
            if (pkey) {
                size_t len = KEY_SIZE;
                EVP_PKEY_get_raw_public_key(pkey, id.keypair.public_key.data(), &len);
                EVP_PKEY_free(pkey);
            }
            id.node_id = hash_public_key(id.keypair.public_key);
            id.network_id = network_id;
            return id;
        }
    }

    // Otherwise generate a new keypair and save to file
    Identity id = Identity::create(network_id);
    std::ofstream out(file_path, std::ios::binary);
    if (out.is_open()) {
        out.write(reinterpret_cast<const char*>(id.keypair.private_key.data()), id.keypair.private_key.size());
    }
    return id;
}
