#include "aegis/invite/invite.hpp"
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
std::string encode_invite(const InvitePayload& payload) {
    uint8_t name_len = (uint8_t)(std::min)(payload.network_name.size(), (size_t)64);
    std::vector<uint8_t> buf;
    buf.reserve(107 + 1 + name_len);

    buf.insert(buf.end(), payload.network_id.begin(), payload.network_id.end());
    buf.insert(buf.end(), payload.bootstrap_pubkey.begin(), payload.bootstrap_pubkey.end());
    buf.insert(buf.end(), payload.creator_node_id.begin(), payload.creator_node_id.end());

    buf.push_back((uint8_t)(payload.bootstrap_endpoint.ip >> 24));
    buf.push_back((uint8_t)(payload.bootstrap_endpoint.ip >> 16));
    buf.push_back((uint8_t)(payload.bootstrap_endpoint.ip >> 8));
    buf.push_back((uint8_t)(payload.bootstrap_endpoint.ip));

    buf.push_back((uint8_t)(payload.bootstrap_endpoint.port >> 8));
    buf.push_back((uint8_t)(payload.bootstrap_endpoint.port));

    buf.push_back((uint8_t)(payload.bootstrap_prefix >> 24));
    buf.push_back((uint8_t)(payload.bootstrap_prefix >> 16));
    buf.push_back((uint8_t)(payload.bootstrap_prefix >> 8));
    buf.push_back((uint8_t)(payload.bootstrap_prefix));

    buf.push_back(payload.bootstrap_prefix_len);

    buf.push_back(name_len);
    if (name_len > 0) {
        buf.insert(buf.end(), payload.network_name.data(), payload.network_name.data() + name_len);
    }

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
    if (!bytes || bytes->size() < 107) {
        return std::nullopt;
    }

    InvitePayload payload;
    size_t off = 0;

    std::memcpy(payload.network_id.data(), bytes->data() + off, 32); off += 32;
    std::memcpy(payload.bootstrap_pubkey.data(), bytes->data() + off, 32); off += 32;
    std::memcpy(payload.creator_node_id.data(), bytes->data() + off, 32); off += 32;

    payload.bootstrap_endpoint.ip =
        ((uint32_t)(*bytes)[off] << 24) | ((uint32_t)(*bytes)[off + 1] << 16) |
        ((uint32_t)(*bytes)[off + 2] << 8) | (uint32_t)(*bytes)[off + 3];
    off += 4;

    payload.bootstrap_endpoint.port =
        ((uint16_t)(*bytes)[off] << 8) | (uint16_t)(*bytes)[off + 1];
    off += 2;

    payload.bootstrap_prefix =
        ((uint32_t)(*bytes)[off] << 24) | ((uint32_t)(*bytes)[off + 1] << 16) |
        ((uint32_t)(*bytes)[off + 2] << 8) | (uint32_t)(*bytes)[off + 3];
    off += 4;

    payload.bootstrap_prefix_len = (*bytes)[off++];

    if (off < bytes->size()) {
        uint8_t name_len = (*bytes)[off++];
        if (off + name_len <= bytes->size() && name_len > 0) {
            payload.network_name = std::string((const char*)bytes->data() + off, name_len);
        }
    }

    return payload;
}
