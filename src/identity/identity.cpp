#include "aegis/identity/identity.hpp"
#include "aegis/protocol/wire.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace {

constexpr char KEY_BINDING_DOMAIN[] = "aegis-x25519-binding-v1";
constexpr char ROTATION_DOMAIN[] = "aegis-identity-rotation-v1";

std::vector<uint8_t> key_binding_message(const X25519Key& public_key) {
    std::vector<uint8_t> message;
    message.reserve(sizeof(KEY_BINDING_DOMAIN) - 1 + public_key.size());
    message.insert(message.end(), KEY_BINDING_DOMAIN,
                   KEY_BINDING_DOMAIN + sizeof(KEY_BINDING_DOMAIN) - 1);
    message.insert(message.end(), public_key.begin(), public_key.end());
    return message;
}

std::vector<uint8_t> rotation_message(
    const IdentityRotationCertificate& certificate) {
    std::vector<uint8_t> message(sizeof(ROTATION_DOMAIN) - 1 +
        KEY_SIZE + X25519_KEY_SIZE + IDENTITY_SIGNATURE_SIZE +
        KEY_SIZE + X25519_KEY_SIZE + IDENTITY_SIGNATURE_SIZE + 8);
    WireWriter writer(message);
    const std::span<const uint8_t> domain(
        reinterpret_cast<const uint8_t*>(ROTATION_DOMAIN),
        sizeof(ROTATION_DOMAIN) - 1);
    if (!writer.write_bytes(domain) ||
        !writer.write_bytes(certificate.previous_signing_public_key) ||
        !writer.write_bytes(certificate.previous_key_agreement_public_key) ||
        !writer.write_bytes(certificate.previous_key_agreement_binding) ||
        !writer.write_bytes(certificate.next_signing_public_key) ||
        !writer.write_bytes(certificate.next_key_agreement_public_key) ||
        !writer.write_bytes(certificate.next_key_agreement_binding) ||
        !writer.write_u64(certificate.issued_at) || !writer.finished())
        return {};
    return message;
}

bool sign_rotation_message(std::span<const uint8_t> message,
                           const Key& private_key,
                           IdentitySignature& signature) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    size_t signature_size = signature.size();
    const bool signed_message = context &&
        EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(context, signature.data(), &signature_size,
                       message.data(), message.size()) == 1 &&
        signature_size == signature.size();
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    return signed_message;
}

bool verify_rotation_message(std::span<const uint8_t> message,
                             const Key& public_key,
                             const IdentitySignature& signature) {
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    const bool valid = context &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context, signature.data(), signature.size(),
                         message.data(), message.size()) == 1;
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    return valid;
}

Identity public_identity(const Key& signing_key, const X25519Key& agreement_key,
                         const IdentitySignature& binding) {
    Identity identity;
    identity.signing_keypair.public_key = signing_key;
    identity.keypair.public_key = agreement_key;
    identity.key_agreement_binding = binding;
    return identity;
}

bool generate_signing_keypair(SigningKeyPair& keypair) {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* key = nullptr;
    const bool generated = context &&
        EVP_PKEY_keygen_init(context) == 1 &&
        EVP_PKEY_keygen(context, &key) == 1 && key;
    if (context)
        EVP_PKEY_CTX_free(context);
    if (!generated) {
        if (key)
            EVP_PKEY_free(key);
        return false;
    }

    size_t public_size = keypair.public_key.size();
    size_t private_size = keypair.private_key.size();
    const bool extracted =
        EVP_PKEY_get_raw_public_key(
            key, keypair.public_key.data(), &public_size) == 1 &&
        EVP_PKEY_get_raw_private_key(
            key, keypair.private_key.data(), &private_size) == 1 &&
        public_size == keypair.public_key.size() &&
        private_size == keypair.private_key.size();
    EVP_PKEY_free(key);
    if (!extracted)
        keypair = {};
    return extracted;
}

} // namespace

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
    if (!bind_identity_keys(id))
        throw std::runtime_error("failed to create identity signing binding");
    return id;
}

bool bind_identity_keys(Identity& identity) {
    identity.signing_keypair = {};
    identity.key_agreement_binding = {};
    if (!generate_signing_keypair(identity.signing_keypair))
        return false;

    const auto private_key = identity.signing_keypair.private_key;
    return bind_identity_keys(identity, private_key);
}

bool bind_identity_keys(
    Identity& identity, const Key& signing_private_key) {
    identity.signing_keypair.private_key = signing_private_key;
    identity.signing_keypair.public_key = {};
    identity.key_agreement_binding = {};

    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        signing_private_key.data(), signing_private_key.size());
    if (!key)
        return false;
    size_t public_size = identity.signing_keypair.public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key, identity.signing_keypair.public_key.data(),
            &public_size) != 1 ||
        public_size != identity.signing_keypair.public_key.size()) {
        EVP_PKEY_free(key);
        identity.signing_keypair.public_key = {};
        return false;
    }
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const auto message = key_binding_message(identity.keypair.public_key);
    size_t signature_size = identity.key_agreement_binding.size();
    const bool signed_binding = context &&
        EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(
            context, identity.key_agreement_binding.data(), &signature_size,
            message.data(), message.size()) == 1 &&
        signature_size == identity.key_agreement_binding.size();
    if (context)
        EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (!signed_binding) {
        identity.key_agreement_binding = {};
        return false;
    }
    return true;
}

bool verify_key_agreement_binding(const Identity& identity) {
    if (identity.signing_keypair.public_key == Key{} ||
        identity.keypair.public_key == X25519Key{} ||
        identity.key_agreement_binding == IdentitySignature{})
        return false;

    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        identity.signing_keypair.public_key.data(),
        identity.signing_keypair.public_key.size());
    if (!key)
        return false;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const auto message = key_binding_message(identity.keypair.public_key);
    const bool valid = context &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(
            context, identity.key_agreement_binding.data(),
            identity.key_agreement_binding.size(),
            message.data(), message.size()) == 1;
    if (context)
        EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return valid;
}

std::optional<IdentityRotationCertificate>
create_identity_rotation_certificate(
    const Identity& previous_identity, const Identity& next_identity,
    uint64_t issued_at) {
    if (!verify_key_agreement_binding(previous_identity) ||
        !verify_key_agreement_binding(next_identity))
        return std::nullopt;
    IdentityRotationCertificate certificate;
    certificate.previous_signing_public_key =
        previous_identity.signing_keypair.public_key;
    certificate.previous_key_agreement_public_key =
        previous_identity.keypair.public_key;
    certificate.previous_key_agreement_binding =
        previous_identity.key_agreement_binding;
    certificate.next_signing_public_key =
        next_identity.signing_keypair.public_key;
    certificate.next_key_agreement_public_key =
        next_identity.keypair.public_key;
    certificate.next_key_agreement_binding =
        next_identity.key_agreement_binding;
    certificate.issued_at = issued_at;
    const auto message = rotation_message(certificate);
    if (message.empty() || !sign_rotation_message(
            message, previous_identity.signing_keypair.private_key,
            certificate.rotation_signature) ||
        !verify_identity_rotation_certificate(
            certificate, previous_identity.signing_keypair.public_key))
        return std::nullopt;
    return certificate;
}

bool verify_identity_rotation_certificate(
    const IdentityRotationCertificate& certificate,
    const Key& expected_previous_signing_public_key) {
    if (certificate.previous_signing_public_key !=
            expected_previous_signing_public_key ||
        certificate.previous_signing_public_key == Key{} ||
        certificate.next_signing_public_key == Key{} ||
        certificate.previous_key_agreement_public_key == X25519Key{} ||
        certificate.next_key_agreement_public_key == X25519Key{} ||
        certificate.rotation_signature == IdentitySignature{})
        return false;
    const Identity previous = public_identity(
        certificate.previous_signing_public_key,
        certificate.previous_key_agreement_public_key,
        certificate.previous_key_agreement_binding);
    const Identity next = public_identity(
        certificate.next_signing_public_key,
        certificate.next_key_agreement_public_key,
        certificate.next_key_agreement_binding);
    if (!verify_key_agreement_binding(previous) ||
        !verify_key_agreement_binding(next))
        return false;
    const auto message = rotation_message(certificate);
    return !message.empty() && verify_rotation_message(
        message, expected_previous_signing_public_key,
        certificate.rotation_signature);
}

bool Identity::matches_network(const NetworkId& other) const {
    return network_id == other;
}
