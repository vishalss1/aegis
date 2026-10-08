#include "aegis/invite/invite.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>
#include <cstring>
#include <openssl/evp.h>
#include <vector>

static const char BASE64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static std::string base64url_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    uint32_t val = 0;
    int valb = -6;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(BASE64URL_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(BASE64URL_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    return out;
}

static std::optional<std::vector<uint8_t>> base64url_decode(const std::string& in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)BASE64URL_CHARS[i]] = i;

    std::vector<uint8_t> out;
    out.reserve((in.size() * 3) / 4);

    uint32_t val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) return std::nullopt;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(uint8_t((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static const char INVITE_PREFIX[] = "AEGIS1:";
static const char AEGIS2_PREFIX[] = "AEGIS2:";
static constexpr size_t INVITE_FIXED_SIZE = 108;
static constexpr size_t INVITE_MAX_NAME_SIZE = 64;
static constexpr char AEGIS2_SIGNING_DOMAIN[] = "aegis-membership-grant-v2";
static constexpr size_t AEGIS2_FIXED_SIZE = 32 + 32 + 32 + 32 + 8 * 4 + 2 + 64;
static constexpr size_t AEGIS2_MAX_SIZE = AEGIS2_FIXED_SIZE +
    AEGIS2_MAX_PREFIXES * 5 + AEGIS2_MAX_BOOTSTRAP_CANDIDATES * 38;

namespace {

std::optional<std::vector<uint8_t>> aegis2_signed_bytes(
    const Aegis2MembershipGrant& grant) {
    if (grant.allowed_prefixes.size() > AEGIS2_MAX_PREFIXES ||
        grant.bootstrap_candidates.size() > AEGIS2_MAX_BOOTSTRAP_CANDIDATES)
        return std::nullopt;
    std::vector<uint8_t> bytes(AEGIS2_FIXED_SIZE - 64 +
        grant.allowed_prefixes.size() * 5 +
        grant.bootstrap_candidates.size() * 38);
    WireWriter writer(bytes);
    if (!writer.write_bytes(grant.network_id) ||
        !writer.write_bytes(grant.issuer_signing_public_key) ||
        !writer.write_bytes(grant.issuer_node_id) ||
        !writer.write_bytes(grant.enrollment_nonce) ||
        !writer.write_u64(grant.issued_at) ||
        !writer.write_u64(grant.expires_at) ||
        !writer.write_u64(grant.capabilities) ||
        !writer.write_u64(grant.revocation_epoch) ||
        !writer.write_u8(static_cast<uint8_t>(grant.allowed_prefixes.size())))
        return std::nullopt;
    for (const auto& prefix : grant.allowed_prefixes) {
        if (prefix.prefix_len > 32 || !writer.write_u32(prefix.prefix) ||
            !writer.write_u8(prefix.prefix_len))
            return std::nullopt;
    }
    if (!writer.write_u8(static_cast<uint8_t>(grant.bootstrap_candidates.size())))
        return std::nullopt;
    for (const auto& candidate : grant.bootstrap_candidates) {
        if (!writer.write_bytes(candidate.x25519_public_key) ||
            !writer.write_u32(candidate.endpoint.ip) ||
            !writer.write_u16(candidate.endpoint.port))
            return std::nullopt;
    }
    if (!writer.finished())
        return std::nullopt;
    return bytes;
}

bool sign_aegis2(std::span<const uint8_t> message, const Key& private_key,
                 IdentitySignature& signature) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    std::vector<uint8_t> domain_message(
        AEGIS2_SIGNING_DOMAIN,
        AEGIS2_SIGNING_DOMAIN + sizeof(AEGIS2_SIGNING_DOMAIN) - 1);
    domain_message.insert(domain_message.end(), message.begin(), message.end());
    size_t signature_size = signature.size();
    const bool ok = context &&
        EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestSign(context, signature.data(), &signature_size,
                       domain_message.data(), domain_message.size()) == 1 &&
        signature_size == signature.size();
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    return ok;
}

bool verify_aegis2(std::span<const uint8_t> message, const Key& public_key,
                   const IdentitySignature& signature) {
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
    std::vector<uint8_t> domain_message(
        AEGIS2_SIGNING_DOMAIN,
        AEGIS2_SIGNING_DOMAIN + sizeof(AEGIS2_SIGNING_DOMAIN) - 1);
    domain_message.insert(domain_message.end(), message.begin(), message.end());
    const bool ok = context &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context, signature.data(), signature.size(),
                         domain_message.data(), domain_message.size()) == 1;
    if (context) EVP_MD_CTX_free(context);
    if (key) EVP_PKEY_free(key);
    return ok;
}

} // namespace

std::string encode_aegis2_grant(
    const Aegis2MembershipGrant& grant, const Key& issuer_signing_private_key) {
    auto message = aegis2_signed_bytes(grant);
    if (!message) return {};
    IdentitySignature signature{};
    if (!sign_aegis2(*message, issuer_signing_private_key, signature))
        return {};
    if (!verify_aegis2(*message, grant.issuer_signing_public_key, signature))
        return {};
    std::vector<uint8_t> bytes = std::move(*message);
    bytes.insert(bytes.end(), signature.begin(), signature.end());
    return std::string(AEGIS2_PREFIX) + base64url_encode(bytes.data(), bytes.size());
}

bool verify_aegis2_grant_signature(const Aegis2MembershipGrant& grant) {
    auto message = aegis2_signed_bytes(grant);
    return message && verify_aegis2(*message, grant.issuer_signing_public_key,
                                    grant.signature);
}

std::optional<Aegis2MembershipGrant> decode_aegis2_grant(
    const std::string& invite_str) {
    size_t start = invite_str.find_first_not_of(" \t\r\n\"");
    if (start == std::string::npos) return std::nullopt;
    size_t end = invite_str.find_last_not_of(" \t\r\n\"");
    const std::string clean = invite_str.substr(start, end - start + 1);
    const size_t prefix_len = std::strlen(AEGIS2_PREFIX);
    if (clean.size() <= prefix_len || clean.size() > prefix_len +
        ((AEGIS2_MAX_SIZE + 2) / 3) * 4 ||
        clean.compare(0, prefix_len, AEGIS2_PREFIX) != 0)
        return std::nullopt;
    const std::string b64 = clean.substr(prefix_len);
    auto bytes = base64url_decode(b64);
    if (!bytes || bytes->size() < AEGIS2_FIXED_SIZE - 64 + 64 ||
        bytes->size() > AEGIS2_MAX_SIZE ||
        base64url_encode(bytes->data(), bytes->size()) != b64)
        return std::nullopt;
    WireReader reader(*bytes);
    Aegis2MembershipGrant grant;
    const auto network = reader.read_bytes(32);
    const auto issuer_key = reader.read_bytes(32);
    const auto issuer_node = reader.read_bytes(32);
    const auto nonce = reader.read_bytes(32);
    const auto issued = reader.read_u64();
    const auto expires = reader.read_u64();
    const auto capabilities = reader.read_u64();
    const auto revocation_epoch = reader.read_u64();
    const auto prefix_count = reader.read_u8();
    if (!network || !issuer_key || !issuer_node || !nonce || !issued ||
        !expires || !capabilities || !revocation_epoch || !prefix_count ||
        *prefix_count > AEGIS2_MAX_PREFIXES)
        return std::nullopt;
    std::copy(network->begin(), network->end(), grant.network_id.begin());
    std::copy(issuer_key->begin(), issuer_key->end(), grant.issuer_signing_public_key.begin());
    std::copy(issuer_node->begin(), issuer_node->end(), grant.issuer_node_id.begin());
    std::copy(nonce->begin(), nonce->end(), grant.enrollment_nonce.begin());
    grant.issued_at = *issued;
    grant.expires_at = *expires;
    grant.capabilities = *capabilities;
    grant.revocation_epoch = *revocation_epoch;
    for (uint8_t i = 0; i < *prefix_count; ++i) {
        const auto prefix = reader.read_u32();
        const auto length = reader.read_u8();
        if (!prefix || !length || *length > 32) return std::nullopt;
        grant.allowed_prefixes.push_back({*prefix, *length});
    }
    const auto candidate_count = reader.read_u8();
    if (!candidate_count || *candidate_count > AEGIS2_MAX_BOOTSTRAP_CANDIDATES)
        return std::nullopt;
    for (uint8_t i = 0; i < *candidate_count; ++i) {
        const auto key = reader.read_bytes(32);
        const auto ip = reader.read_u32();
        const auto port = reader.read_u16();
        if (!key || !ip || !port) return std::nullopt;
        Aegis2BootstrapCandidate candidate;
        std::copy(key->begin(), key->end(), candidate.x25519_public_key.begin());
        candidate.endpoint.ip = *ip;
        candidate.endpoint.port = *port;
        grant.bootstrap_candidates.push_back(candidate);
    }
    const auto signature = reader.read_bytes(64);
    if (!signature || !reader.finished()) return std::nullopt;
    std::copy(signature->begin(), signature->end(), grant.signature.begin());
    if (!verify_aegis2_grant_signature(grant)) return std::nullopt;
    return grant;
}

std::string encode_invite(const InvitePayload& payload) {
    const uint8_t name_len = static_cast<uint8_t>((std::min)(
        payload.network_name.size(), INVITE_MAX_NAME_SIZE));
    std::vector<uint8_t> buf(INVITE_FIXED_SIZE + name_len);
    WireWriter writer(buf);
    const auto name = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(payload.network_name.data()), name_len);
    if (!writer.write_bytes(payload.network_id) ||
        !writer.write_bytes(payload.bootstrap_pubkey) ||
        !writer.write_bytes(payload.creator_node_id) ||
        !writer.write_u32(payload.bootstrap_endpoint.ip) ||
        !writer.write_u16(payload.bootstrap_endpoint.port) ||
        !writer.write_u32(payload.bootstrap_prefix) ||
        !writer.write_u8(payload.bootstrap_prefix_len) ||
        !writer.write_u8(name_len) || !writer.write_bytes(name) ||
        !writer.finished())
        return {};

    return std::string(INVITE_PREFIX) + base64url_encode(buf.data(), buf.size());
}

std::optional<InvitePayload> decode_invite(const std::string& invite_str) {
    size_t start = invite_str.find_first_not_of(" \t\r\n\"");
    if (start == std::string::npos) return std::nullopt;
    size_t end = invite_str.find_last_not_of(" \t\r\n\"");
    std::string clean = invite_str.substr(start, end - start + 1);

    size_t prefix_len = std::strlen(INVITE_PREFIX);
    if (clean.size() <= prefix_len ||
        clean.compare(0, prefix_len, INVITE_PREFIX) != 0) {
        return std::nullopt;
    }

    std::string b64 = clean.substr(prefix_len);
    auto bytes = base64url_decode(b64);
    if (!bytes || bytes->size() < INVITE_FIXED_SIZE ||
        base64url_encode(bytes->data(), bytes->size()) != b64) {
        return std::nullopt;
    }

    InvitePayload payload;
    WireReader reader(*bytes);
    const auto network_id = reader.read_bytes(NETWORK_ID_SIZE);
    const auto bootstrap_pubkey = reader.read_bytes(KEY_SIZE);
    const auto creator_node_id = reader.read_bytes(NODE_ID_SIZE);
    const auto endpoint_ip = reader.read_u32();
    const auto endpoint_port = reader.read_u16();
    const auto bootstrap_prefix = reader.read_u32();
    const auto bootstrap_prefix_len = reader.read_u8();
    const auto name_len = reader.read_u8();
    if (!network_id || !bootstrap_pubkey || !creator_node_id || !endpoint_ip ||
        !endpoint_port || !bootstrap_prefix || !bootstrap_prefix_len ||
        !name_len || *bootstrap_prefix_len > 32 ||
        *name_len > INVITE_MAX_NAME_SIZE)
        return std::nullopt;
    const auto name = reader.read_bytes(*name_len);
    if (!name || !reader.finished())
        return std::nullopt;

    std::copy(network_id->begin(), network_id->end(), payload.network_id.begin());
    std::copy(bootstrap_pubkey->begin(), bootstrap_pubkey->end(),
              payload.bootstrap_pubkey.begin());
    std::copy(creator_node_id->begin(), creator_node_id->end(),
              payload.creator_node_id.begin());
    payload.bootstrap_endpoint.ip = *endpoint_ip;
    payload.bootstrap_endpoint.port = *endpoint_port;
    payload.bootstrap_prefix = *bootstrap_prefix;
    payload.bootstrap_prefix_len = *bootstrap_prefix_len;
    payload.network_name.assign(
        reinterpret_cast<const char*>(name->data()), name->size());

    return payload;
}
