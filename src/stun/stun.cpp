#include "aegis/stun/stun.hpp"
#include "aegis/crypto/random.hpp"
#include "aegis/protocol/wire.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <cstdio>
#include <cstring>

static constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

std::vector<uint8_t> create_stun_binding_request(const uint8_t transaction_id[12]) {
    if (!transaction_id)
        return {};
    std::vector<uint8_t> req(20, 0);
    WireWriter writer(req);
    if (!writer.write_u16(0x0001) || !writer.write_u16(0) ||
        !writer.write_u32(STUN_MAGIC_COOKIE) ||
        !writer.write_bytes(std::span<const uint8_t>(transaction_id, 12)) ||
        !writer.finished())
        return {};
    return req;
}

std::optional<Endpoint> parse_stun_binding_response(
    const uint8_t* data, size_t len, const uint8_t expected_tx_id[12]) {
    if (!data || len < 20) return std::nullopt;

    WireReader reader(std::span<const uint8_t>(data, len));
    const auto msg_type = reader.read_u16();
    const auto msg_len = reader.read_u16();
    const auto cookie = reader.read_u32();
    const auto transaction_id = reader.read_bytes(12);
    if (!msg_type || !msg_len || !cookie || !transaction_id ||
        (*msg_type != 0x0101 && *msg_type != 0x0111) ||
        *cookie != STUN_MAGIC_COOKIE || (*msg_len % 4) != 0 ||
        len != 20u + static_cast<size_t>(*msg_len))
        return std::nullopt;
    if (expected_tx_id &&
        std::memcmp(transaction_id->data(), expected_tx_id, 12) != 0)
        return std::nullopt;

    std::optional<Endpoint> mapped;
    while (!reader.finished()) {
        const auto attr_type = reader.read_u16();
        const auto attr_len = reader.read_u16();
        if (!attr_type || !attr_len)
            return std::nullopt;
        const auto value = reader.read_bytes(*attr_len);
        if (!value)
            return std::nullopt;
        const size_t padded_len =
            (static_cast<size_t>(*attr_len) + 3u) & ~size_t{3u};
        if (!reader.read_bytes(padded_len - *attr_len))
            return std::nullopt;

        if (*attr_type != 0x0020)
            continue;

        WireReader address(*value);
        const auto reserved = address.read_u8();
        const auto family = address.read_u8();
        const auto xor_port = address.read_u16();
        if (!reserved || !family || !xor_port || *reserved != 0)
            return std::nullopt;
        if (*family == 0x02) {
            if (*attr_len != 20)
                return std::nullopt;
            continue; // IPv6 discovery is not implemented yet.
        }
        if (*family != 0x01 || *attr_len != 8 || mapped)
            return std::nullopt;
        const auto xor_ip = address.read_u32();
        if (!xor_ip || !address.finished())
            return std::nullopt;

        Endpoint endpoint;
        endpoint.ip = htonl(*xor_ip ^ STUN_MAGIC_COOKIE);
        endpoint.port = htons(
            *xor_port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16));
        mapped = endpoint;
    }
    return mapped;
}

std::optional<Endpoint> stun_discover(
    const std::string& stun_host, uint16_t stun_port,
    uint16_t local_port, int timeout_ms, RandomSource& random) {

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return std::nullopt;

    if (local_port > 0) {
        struct sockaddr_in local_addr = {};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(local_port);
        bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr));
    }

    DWORD tv = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", stun_port);

    if (getaddrinfo(stun_host.c_str(), port_str, &hints, &res) != 0 || !res) {
        closesocket(sock);
        return std::nullopt;
    }

    std::array<uint8_t, 12> tx_id{};
    if (!random.fill(tx_id)) {
        freeaddrinfo(res);
        closesocket(sock);
        return std::nullopt;
    }

    auto req = create_stun_binding_request(tx_id.data());
    if (sendto(sock, (const char*)req.data(), (int)req.size(), 0,
               res->ai_addr, (int)res->ai_addrlen) <= 0) {
        freeaddrinfo(res);
        closesocket(sock);
        return std::nullopt;
    }
    freeaddrinfo(res);

    uint8_t buf[512];
    int r = recv(sock, (char*)buf, sizeof(buf), 0);
    closesocket(sock);

    if (r < 20) return std::nullopt;

    return parse_stun_binding_response(buf, r, tx_id.data());
}
