#include "aegis/crypto/x25519.hpp"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <cstring>
#include <cstdio>

X25519KeyPair x25519_generate_keypair() {
    X25519KeyPair kp{};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        fprintf(stderr, "[x25519] EVP_PKEY_CTX_new_id failed\n");
        return kp;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return kp;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_keygen failed\n");
        EVP_PKEY_CTX_free(ctx);
        return kp;
    }
    EVP_PKEY_CTX_free(ctx);

    size_t len = X25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &len) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_get_raw_private_key failed\n");
        EVP_PKEY_free(pkey);
        return kp;
    }

    len = X25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &len) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_get_raw_public_key failed\n");
        EVP_PKEY_free(pkey);
        return kp;
    }

    EVP_PKEY_free(pkey);
    return kp;
}

std::optional<X25519Key> x25519_derive_shared_secret(
    const X25519Key& my_private,
    const X25519Key& their_public
) {
    // Load our private key from raw bytes
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        my_private.data(), my_private.size());
    if (!priv) {
        fprintf(stderr, "[x25519] EVP_PKEY_new_raw_private_key failed\n");
        return std::nullopt;
    }

    // Load their public key from raw bytes
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        their_public.data(), their_public.size());
    if (!pub) {
        fprintf(stderr, "[x25519] EVP_PKEY_new_raw_public_key failed\n");
        EVP_PKEY_free(priv);
        return std::nullopt;
    }

    EVP_PKEY_CTX* derive = EVP_PKEY_CTX_new(priv, nullptr);
    if (!derive) {
        fprintf(stderr, "[x25519] EVP_PKEY_CTX_new failed\n");
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    if (EVP_PKEY_derive_init(derive) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_derive_init failed\n");
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    if (EVP_PKEY_derive_set_peer(derive, pub) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_derive_set_peer failed\n");
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive, nullptr, &secret_len) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_derive (size query) failed\n");
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    X25519Key secret{};
    if (secret_len != X25519_KEY_SIZE) {
        fprintf(stderr, "[x25519] unexpected shared secret length: %zu\n", secret_len);
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    if (EVP_PKEY_derive(derive, secret.data(), &secret_len) <= 0) {
        fprintf(stderr, "[x25519] EVP_PKEY_derive failed\n");
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return std::nullopt;
    }

    EVP_PKEY_CTX_free(derive);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return secret;
}
