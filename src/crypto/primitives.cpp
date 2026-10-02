#include "aegis/crypto/primitives.hpp"
#include "aegis/crypto/secret.hpp"

#include <algorithm>
#include <limits>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace {

const EVP_MD* digest_for(CryptoHashAlgorithm algorithm) {
    switch (algorithm) {
    case CryptoHashAlgorithm::Sha256:
        return EVP_sha256();
    case CryptoHashAlgorithm::Blake2s256:
        return EVP_blake2s256();
    }
    return nullptr;
}

bool fits_openssl_int(size_t size) {
    return size <= static_cast<size_t>((std::numeric_limits<int>::max)());
}

} // namespace

std::optional<CryptoHash> transcript_hash(
    CryptoHashAlgorithm algorithm,
    std::initializer_list<std::span<const uint8_t>> fragments) {
    const EVP_MD* digest = digest_for(algorithm);
    if (!digest)
        return std::nullopt;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context)
        return std::nullopt;

    bool ok = EVP_DigestInit_ex(context, digest, nullptr) == 1;
    for (const auto fragment : fragments) {
        if (!ok)
            break;
        if (!fragment.empty())
            ok = EVP_DigestUpdate(
                     context, fragment.data(), fragment.size()) == 1;
    }

    CryptoHash result{};
    unsigned int result_size = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(context, result.data(), &result_size) == 1 &&
             result_size == result.size();
    EVP_MD_CTX_free(context);

    if (!ok)
        return std::nullopt;
    return result;
}

std::optional<CryptoHash> hmac_hash(
    CryptoHashAlgorithm algorithm,
    std::span<const uint8_t> key,
    std::span<const uint8_t> message) {
    constexpr size_t block_size = 64;
    SecretBytes<block_size> key_block;
    if (key.size() > block_size) {
        auto hashed_key = transcript_hash(algorithm, {key});
        if (!hashed_key)
            return std::nullopt;
        std::copy(hashed_key->begin(), hashed_key->end(), key_block.begin());
        OPENSSL_cleanse(hashed_key->data(), hashed_key->size());
    } else {
        std::copy(key.begin(), key.end(), key_block.begin());
    }

    SecretBytes<block_size> inner_pad;
    SecretBytes<block_size> outer_pad;
    for (size_t i = 0; i < block_size; ++i) {
        inner_pad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36u);
        outer_pad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5cu);
    }

    auto inner = transcript_hash(algorithm, {inner_pad, message});
    if (!inner)
        return std::nullopt;
    auto result = transcript_hash(algorithm, {outer_pad, *inner});
    OPENSSL_cleanse(inner->data(), inner->size());
    return result;
}

bool hkdf(
    CryptoHashAlgorithm algorithm,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    std::span<uint8_t> output) {
    const EVP_MD* digest = digest_for(algorithm);
    if (!digest || !fits_openssl_int(input_key_material.size()) ||
        !fits_openssl_int(salt.size()) || !fits_openssl_int(info.size()) ||
        output.size() > 255u * CryptoHash{}.size())
        return false;
    if (output.empty())
        return true;

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!context)
        return false;

    bool ok = EVP_PKEY_derive_init(context) == 1 &&
              EVP_PKEY_CTX_set_hkdf_md(context, digest) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_salt(
                  context, salt.data(), static_cast<int>(salt.size())) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_key(
                  context, input_key_material.data(),
                  static_cast<int>(input_key_material.size())) == 1 &&
              EVP_PKEY_CTX_add1_hkdf_info(
                  context, info.data(), static_cast<int>(info.size())) == 1;

    std::vector<uint8_t> derived(output.size());
    size_t derived_size = derived.size();
    if (ok)
        ok = EVP_PKEY_derive(
                 context, derived.data(), &derived_size) == 1 &&
             derived_size == derived.size();
    EVP_PKEY_CTX_free(context);

    if (!ok) {
        OPENSSL_cleanse(derived.data(), derived.size());
        return false;
    }
    std::copy(derived.begin(), derived.end(), output.begin());
    OPENSSL_cleanse(derived.data(), derived.size());
    return true;
}

bool constant_time_equal(
    std::span<const uint8_t> left,
    std::span<const uint8_t> right) {
    if (left.size() != right.size())
        return false;
    if (left.empty())
        return true;
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}
