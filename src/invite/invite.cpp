#include "aegis/invite/invite.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>
#include <cstring>
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
static constexpr size_t INVITE_FIXED_SIZE = 108;
static constexpr size_t INVITE_MAX_NAME_SIZE = 64;

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
