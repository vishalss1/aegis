#include "aegis/cli/identity_store.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <windows.h>
#include <shlobj.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::array<uint8_t, 7> IDENTITY_STORE_MAGIC{
    'A', 'E', 'G', 'I', 'S', 'I', 'D'};
constexpr uint8_t IDENTITY_STORE_VERSION = 1;
constexpr size_t IDENTITY_STORE_HEADER_SIZE = 8;
constexpr size_t IDENTITY_STORE_X25519_OFFSET = IDENTITY_STORE_HEADER_SIZE;
constexpr size_t IDENTITY_STORE_SIGNING_OFFSET =
    IDENTITY_STORE_X25519_OFFSET + KEY_SIZE;
constexpr size_t IDENTITY_STORE_BINDING_OFFSET =
    IDENTITY_STORE_SIGNING_OFFSET + KEY_SIZE;
constexpr size_t IDENTITY_STORE_CHECKSUM_OFFSET =
    IDENTITY_STORE_BINDING_OFFSET + IDENTITY_SIGNATURE_SIZE;
constexpr size_t IDENTITY_STORE_CHECKSUM_SIZE = 32;
constexpr size_t IDENTITY_STORE_V1_SIZE =
    IDENTITY_STORE_CHECKSUM_OFFSET + IDENTITY_STORE_CHECKSUM_SIZE;
constexpr size_t LEGACY_IDENTITY_SIZE = KEY_SIZE;
constexpr size_t MAX_IDENTITY_FILE_SIZE = IDENTITY_STORE_V1_SIZE;

std::array<uint8_t, IDENTITY_STORE_CHECKSUM_SIZE> checksum(
    std::span<const uint8_t> bytes) {
    std::array<uint8_t, IDENTITY_STORE_CHECKSUM_SIZE> digest{};
    unsigned int digest_size = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &digest_size,
                   EVP_sha256(), nullptr) != 1 ||
        digest_size != digest.size())
        throw std::runtime_error("failed to checksum identity credentials");
    return digest;
}

std::array<uint8_t, IDENTITY_STORE_V1_SIZE> encode_identity(
    const Identity& identity) {
    if (!verify_key_agreement_binding(identity) ||
        identity.node_id != hash_public_key(identity.keypair.public_key))
        throw std::runtime_error("refusing to save invalid identity binding");

    std::array<uint8_t, IDENTITY_STORE_V1_SIZE> bytes{};
    std::copy(IDENTITY_STORE_MAGIC.begin(), IDENTITY_STORE_MAGIC.end(),
              bytes.begin());
    bytes[7] = IDENTITY_STORE_VERSION;
    std::copy(identity.keypair.private_key.begin(),
              identity.keypair.private_key.end(),
              bytes.begin() + IDENTITY_STORE_X25519_OFFSET);
    std::copy(identity.signing_keypair.private_key.begin(),
              identity.signing_keypair.private_key.end(),
              bytes.begin() + IDENTITY_STORE_SIGNING_OFFSET);
    std::copy(identity.key_agreement_binding.begin(),
              identity.key_agreement_binding.end(),
              bytes.begin() + IDENTITY_STORE_BINDING_OFFSET);
    const auto digest = checksum(std::span<const uint8_t>(
        bytes.data(), IDENTITY_STORE_CHECKSUM_OFFSET));
    std::copy(digest.begin(), digest.end(),
              bytes.begin() + IDENTITY_STORE_CHECKSUM_OFFSET);
    return bytes;
}

void write_identity_atomic(const std::string& path, const Identity& identity) {
    const auto bytes = encode_identity(identity);
    std::string temporary_path;
    HANDLE file = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        temporary_path = path + ".tmp." +
            std::to_string(GetCurrentProcessId()) + "." +
            std::to_string(attempt);
        file = CreateFileA(
            temporary_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (file != INVALID_HANDLE_VALUE)
            break;
        if (GetLastError() != ERROR_FILE_EXISTS &&
            GetLastError() != ERROR_ALREADY_EXISTS)
            throw std::runtime_error("failed to create temporary identity file");
    }
    if (file == INVALID_HANDLE_VALUE)
        throw std::runtime_error("identity temporary-file names exhausted");

    DWORD written = 0;
    const bool wrote = WriteFile(
        file, bytes.data(), static_cast<DWORD>(bytes.size()), &written,
        nullptr) != 0 && written == static_cast<DWORD>(bytes.size()) &&
        FlushFileBuffers(file) != 0;
    CloseHandle(file);
    if (!wrote) {
        DeleteFileA(temporary_path.c_str());
        throw std::runtime_error("failed to write identity credentials");
    }
    if (!MoveFileExA(
            temporary_path.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(temporary_path.c_str());
        throw std::runtime_error("failed to atomically replace identity file");
    }
}

std::vector<uint8_t> read_identity_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open())
        throw std::runtime_error("identity file exists but cannot be opened");
    const auto end = in.tellg();
    if (end < 0 || static_cast<uint64_t>(end) > MAX_IDENTITY_FILE_SIZE)
        throw std::runtime_error("identity file exceeds the supported size");
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    in.seekg(0, std::ios::beg);
    if (!bytes.empty())
        in.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!in || in.gcount() != static_cast<std::streamsize>(bytes.size()))
        throw std::runtime_error("identity file read was incomplete");
    return bytes;
}

X25519Key derive_x25519_public(const X25519PrivateKey& private_key) {
    X25519Key public_key{};
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    if (!key)
        throw std::runtime_error("invalid X25519 identity private key");
    size_t public_size = public_key.size();
    const bool derived = EVP_PKEY_get_raw_public_key(
        key, public_key.data(), &public_size) == 1 &&
        public_size == public_key.size();
    EVP_PKEY_free(key);
    if (!derived)
        throw std::runtime_error("failed to derive X25519 identity public key");
    return public_key;
}

Identity decode_legacy_identity(
    const std::vector<uint8_t>& bytes, const NetworkId& network_id) {
    Identity identity;
    std::copy(bytes.begin(), bytes.end(), identity.keypair.private_key.begin());
    identity.keypair.public_key =
        derive_x25519_public(identity.keypair.private_key);
    identity.node_id = hash_public_key(identity.keypair.public_key);
    identity.network_id = network_id;
    if (!bind_identity_keys(identity))
        throw std::runtime_error("failed to migrate legacy identity keys");
    return identity;
}

Identity decode_v1_identity(
    const std::vector<uint8_t>& bytes, const NetworkId& network_id) {
    if (bytes.size() != IDENTITY_STORE_V1_SIZE ||
        !std::equal(IDENTITY_STORE_MAGIC.begin(), IDENTITY_STORE_MAGIC.end(),
                    bytes.begin()) ||
        bytes[7] != IDENTITY_STORE_VERSION)
        throw std::runtime_error("unsupported or malformed identity format");

    const auto expected = checksum(std::span<const uint8_t>(
        bytes.data(), IDENTITY_STORE_CHECKSUM_OFFSET));
    if (CRYPTO_memcmp(
            expected.data(), bytes.data() + IDENTITY_STORE_CHECKSUM_OFFSET,
            expected.size()) != 0)
        throw std::runtime_error("identity credential checksum mismatch");

    Identity identity;
    std::copy_n(bytes.begin() + IDENTITY_STORE_X25519_OFFSET, KEY_SIZE,
                identity.keypair.private_key.begin());
    identity.keypair.public_key =
        derive_x25519_public(identity.keypair.private_key);
    identity.node_id = hash_public_key(identity.keypair.public_key);
    identity.network_id = network_id;

    Key signing_private{};
    std::copy_n(bytes.begin() + IDENTITY_STORE_SIGNING_OFFSET, KEY_SIZE,
                signing_private.begin());
    IdentitySignature stored_binding{};
    std::copy_n(bytes.begin() + IDENTITY_STORE_BINDING_OFFSET,
                IDENTITY_SIGNATURE_SIZE, stored_binding.begin());
    if (!bind_identity_keys(identity, signing_private) ||
        identity.key_agreement_binding != stored_binding ||
        !verify_key_agreement_binding(identity))
        throw std::runtime_error("identity signing binding is invalid");
    return identity;
}

bool identity_file_exists(const std::string& path) {
    const DWORD attributes = GetFileAttributesA(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
        return true;
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        return false;
    throw std::runtime_error("failed to inspect identity file path");
}

} // namespace

std::string get_identity_file_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::string dir = std::string(path) + "\\Aegis";
        CreateDirectoryA(dir.c_str(), NULL);
        return dir + "\\identity.bin";
    }
    return "identity.bin";
}

Identity load_or_create_identity(
    const NetworkId& network_id, const std::string& custom_path) {
    const std::string file_path = custom_path.empty()
        ? get_identity_file_path() : custom_path;

    if (identity_file_exists(file_path)) {
        const auto bytes = read_identity_file(file_path);
        if (bytes.size() == LEGACY_IDENTITY_SIZE) {
            auto identity = decode_legacy_identity(bytes, network_id);
            write_identity_atomic(file_path, identity);
            return identity;
        }
        return decode_v1_identity(bytes, network_id);
    }

    const Identity identity = Identity::create(network_id);
    write_identity_atomic(file_path, identity);
    return identity;
}
