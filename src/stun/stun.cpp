#include "aegis/stun/stun.hpp"
#include "aegis/crypto/random.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <cstdio>
#include <cstring>

static constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

std::vector<uint8_t> create_stun_binding_request(const uint8_t transaction_id[12]) {
    std::vector<uint8_t> req(20, 0);
    req[0] = 0x00; // Type: 0x0001 (Binding Request)
    req[1] = 0x01;
    req[2] = 0x00; // Length: 0
    req[3] = 0x00;

    req[4] = static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 24) & 0xFFu);
    req[5] = static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 16) & 0xFFu);
    req[6] = static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 8) & 0xFFu);
    req[7] = static_cast<uint8_t>(STUN_MAGIC_COOKIE & 0xFFu);

    std::memcpy(req.data() + 8, transaction_id, 12);
    return req;
}

std::optional<Endpoint> parse_stun_binding_response(
    const uint8_t* data, size_t len, const uint8_t expected_tx_id[12]) {
    if (!data || len < 20) return std::nullopt;

    // Check type: 0x0101 (Binding Response) or 0x0111 (Success Response)
    uint16_t msg_type = ((uint16_t)data[0] << 8) | data[1];
    if (msg_type != 0x0101 && msg_type != 0x0111) return std::nullopt;

    uint32_t cookie = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                      ((uint32_t)data[6] << 8) | data[7];
    if (cookie != STUN_MAGIC_COOKIE) return std::nullopt;

    if (expected_tx_id && std::memcmp(data + 8, expected_tx_id, 12) != 0) return std::nullopt;

    uint16_t msg_len = ((uint16_t)data[2] << 8) | data[3];
    if (len < 20 + msg_len) return std::nullopt;

    size_t off = 20;
    while (off + 4 <= 20 + msg_len) {
        uint16_t attr_type = ((uint16_t)data[off] << 8) | data[off + 1];
        uint16_t attr_len  = ((uint16_t)data[off + 2] << 8) | data[off + 3];
        off += 4;

        if (off + attr_len > len) break;

        // XOR-MAPPED-ADDRESS attribute: 0x0020
        if (attr_type == 0x0020 && attr_len >= 8) {
            uint8_t family = data[off + 1];
            if (family == 0x01) { // IPv4
                uint16_t xor_port = ((uint16_t)data[off + 2] << 8) | data[off + 3];
                uint32_t xor_ip   = ((uint32_t)data[off + 4] << 24) | ((uint32_t)data[off + 5] << 16) |
                                    ((uint32_t)data[off + 6] << 8)  | data[off + 7];

                uint16_t port = xor_port ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
                uint32_t ip   = xor_ip ^ STUN_MAGIC_COOKIE;

                Endpoint ep;
                ep.ip = htonl(ip);
                ep.port = htons(port);
                return ep;
            }
        }

        // Align attribute to 4-byte boundary
        off += (attr_len + 3) & ~3;
    }

    return std::nullopt;
}

std::optional<Endpoint> stun_discover(
    const std::string& stun_host, uint16_t stun_port,
    uint16_t local_port, int timeout_ms) {

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
    if (!secure_random_bytes(tx_id)) {
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
