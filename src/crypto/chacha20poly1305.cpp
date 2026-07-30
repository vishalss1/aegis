#include "aegis/crypto/chacha20poly1305.hpp"
#include <openssl/evp.h>
#include <cstdio>

bool chacha20_poly1305_encrypt(
    const ChaCha20Poly1305Key& key,
    const ChaCha20Poly1305Nonce& nonce,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out,
    const uint8_t* aad,
    size_t aad_len
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[aead] EVP_CIPHER_CTX_new failed\n");
        return false;
    }

    int out_len = 0;
    int final_len = 0;
    bool ok = false;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            (int)CHACHA20_POLY1305_NONCE_SIZE, nullptr) != 1)
        goto done;

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        goto done;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, (int)aad_len) != 1)
            goto done;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext_out, &out_len, plaintext, (int)plaintext_len) != 1)
        goto done;

    if (EVP_EncryptFinal_ex(ctx, nullptr, &final_len) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            (int)CHACHA20_POLY1305_TAG_SIZE, tag_out) != 1)
        goto done;

    ok = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool chacha20_poly1305_decrypt(
    const ChaCha20Poly1305Key& key,
    const ChaCha20Poly1305Nonce& nonce,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext_out,
    const uint8_t* aad,
    size_t aad_len
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[aead] EVP_CIPHER_CTX_new failed\n");
        return false;
    }

    int out_len = 0;
    int final_len = 0;
    bool ok = false;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            (int)CHACHA20_POLY1305_NONCE_SIZE, nullptr) != 1)
        goto done;

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        goto done;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, (int)aad_len) != 1)
            goto done;
    }

    if (EVP_DecryptUpdate(ctx, plaintext_out, &out_len,
                          ciphertext, (int)ciphertext_len) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            (int)CHACHA20_POLY1305_TAG_SIZE, (void*)tag) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(ctx, nullptr, &final_len) != 1)
        goto done;

    ok = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
