#include "aegis/identity/revocation.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>
#include <openssl/evp.h>

namespace {

constexpr uint8_t REVOCATION_WIRE_VERSION = 1;
constexpr char REVOCATION_DOMAIN[] = "aegis-membership-revocation-v1";
constexpr size_t REVOCATION_BODY_SIZE = 32 + 32 + 32 + 8 + 8;

std::vector<uint8_t> signed_body(const MembershipRevocation& revocation) {
    std::vector<uint8_t> body(REVOCATION_BODY_SIZE);
    WireWriter writer(body);
    if (!writer.write_bytes(revocation.network_id) ||
        !writer.write_bytes(revocation.issuer_signing_public_key) ||
        !writer.write_bytes(revocation.enrollment_nonce) ||
        !writer.write_u64(revocation.revocation_epoch) ||
        !writer.write_u64(revocation.issued_at) || !writer.finished())
        return {};
    return body;
}

std::vector<uint8_t> domain_message(const MembershipRevocation& revocation) {
    auto message = std::vector<uint8_t>(
        REVOCATION_DOMAIN,
        REVOCATION_DOMAIN + sizeof(REVOCATION_DOMAIN) - 1);
    const auto body = signed_body(revocation);
    message.insert(message.end(), body.begin(), body.end());
    return message;
}

} // namespace

std::optional<MembershipRevocation> sign_membership_revocation(
    const NetworkId& network_id, const Key& issuer_signing_public_key,
    const Key& issuer_signing_private_key, const Key& enrollment_nonce,
    uint64_t revocation_epoch, uint64_t issued_at) {
    if (network_id == NetworkId{} || issuer_signing_public_key == Key{} ||
        enrollment_nonce == Key{})
        return std::nullopt;
    MembershipRevocation revocation;
    revocation.network_id = network_id;
    revocation.issuer_signing_public_key = issuer_signing_public_key;
    revocation.enrollment_nonce = enrollment_nonce;
    revocation.revocation_epoch = revocation_epoch;
    revocation.issued_at = issued_at;
    const auto message = domain_message(revocation);
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, issuer_signing_private_key.data(),
        issuer_signing_private_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    size_t signature_size = revocation.signature.size();
    const bool signed_ok = context &&
        EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(context, revocation.signature.data(), &signature_size,
                       message.data(), message.size()) == 1 &&
        signature_size == revocation.signature.size();
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    if (!signed_ok || !verify_membership_revocation(revocation))
        return std::nullopt;
    return revocation;
}

bool verify_membership_revocation(const MembershipRevocation& revocation) {
    if (revocation.network_id == NetworkId{} ||
        revocation.issuer_signing_public_key == Key{} ||
        revocation.enrollment_nonce == Key{} ||
        revocation.signature == IdentitySignature{})
        return false;
    const auto message = domain_message(revocation);
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        revocation.issuer_signing_public_key.data(),
        revocation.issuer_signing_public_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    const bool valid = context &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context, revocation.signature.data(),
                         revocation.signature.size(), message.data(),
                         message.size()) == 1;
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    return valid;
}

std::optional<std::vector<uint8_t>> serialize_membership_revocations(
    const std::vector<MembershipRevocation>& revocations) {
    if (revocations.empty() ||
        revocations.size() > MEMBERSHIP_REVOCATION_MAX_RECORDS)
        return std::nullopt;
    std::vector<uint8_t> bytes(2 +
        revocations.size() * MEMBERSHIP_REVOCATION_RECORD_SIZE);
    WireWriter writer(bytes);
    if (!writer.write_u8(REVOCATION_WIRE_VERSION) ||
        !writer.write_u8(static_cast<uint8_t>(revocations.size())))
        return std::nullopt;
    for (const auto& revocation : revocations) {
        if (!verify_membership_revocation(revocation) ||
            !writer.write_bytes(revocation.network_id) ||
            !writer.write_bytes(revocation.issuer_signing_public_key) ||
            !writer.write_bytes(revocation.enrollment_nonce) ||
            !writer.write_u64(revocation.revocation_epoch) ||
            !writer.write_u64(revocation.issued_at) ||
            !writer.write_bytes(revocation.signature))
            return std::nullopt;
    }
    if (!writer.finished()) return std::nullopt;
    return bytes;
}

std::optional<std::vector<MembershipRevocation>>
deserialize_membership_revocations(const uint8_t* data, size_t length) {
    if (!data || length < 2 || length > 2 +
        MEMBERSHIP_REVOCATION_MAX_RECORDS * MEMBERSHIP_REVOCATION_RECORD_SIZE)
        return std::nullopt;
    WireReader reader(std::span<const uint8_t>(data, length));
    const auto version = reader.read_u8();
    const auto count = reader.read_u8();
    if (!version || *version != REVOCATION_WIRE_VERSION || !count ||
        *count == 0 || *count > MEMBERSHIP_REVOCATION_MAX_RECORDS ||
        length != 2 + static_cast<size_t>(*count) *
            MEMBERSHIP_REVOCATION_RECORD_SIZE)
        return std::nullopt;
    std::vector<MembershipRevocation> result;
    result.reserve(*count);
    for (uint8_t i = 0; i < *count; ++i) {
        MembershipRevocation revocation;
        const auto network = reader.read_bytes(32);
        const auto issuer = reader.read_bytes(32);
        const auto nonce = reader.read_bytes(32);
        const auto epoch = reader.read_u64();
        const auto issued = reader.read_u64();
        const auto signature = reader.read_bytes(64);
        if (!network || !issuer || !nonce || !epoch || !issued || !signature)
            return std::nullopt;
        std::copy(network->begin(), network->end(), revocation.network_id.begin());
        std::copy(issuer->begin(), issuer->end(),
                  revocation.issuer_signing_public_key.begin());
        std::copy(nonce->begin(), nonce->end(), revocation.enrollment_nonce.begin());
        revocation.revocation_epoch = *epoch;
        revocation.issued_at = *issued;
        std::copy(signature->begin(), signature->end(), revocation.signature.begin());
        if (!verify_membership_revocation(revocation)) return std::nullopt;
        result.push_back(revocation);
    }
    if (!reader.finished()) return std::nullopt;
    return result;
}

bool MembershipRevocationStore::add(const MembershipRevocation& revocation) {
    if (!verify_membership_revocation(revocation)) return false;
    std::lock_guard lock(mutex_);
    auto found = std::find_if(records_.begin(), records_.end(),
        [&](const MembershipRevocation& current) {
            return current.network_id == revocation.network_id &&
                current.issuer_signing_public_key ==
                    revocation.issuer_signing_public_key &&
                current.enrollment_nonce == revocation.enrollment_nonce;
        });
    if (found != records_.end()) {
        if (found->revocation_epoch >= revocation.revocation_epoch)
            return false;
        *found = revocation;
        return true;
    }
    if (records_.size() >= MEMBERSHIP_REVOCATION_MAX_STORED)
        return false;
    records_.push_back(revocation);
    return true;
}

std::vector<MembershipRevocation> MembershipRevocationStore::snapshot() const {
    std::lock_guard lock(mutex_);
    return records_;
}

size_t MembershipRevocationStore::size() const {
    std::lock_guard lock(mutex_);
    return records_.size();
}
