#pragma once

#include "aegis/net/ip_address.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <winsock2.h>

// A UDP endpoint. The address is family-tagged; `port` stays in network byte
// order to match the existing callers.
struct Endpoint {
    IPAddress address{};
    uint16_t port = 0;

    Endpoint() = default;
    Endpoint(uint32_t ipv4_network_order, uint16_t port_network_order) noexcept
        : address(IPAddress::from_ipv4(ntohl(ipv4_network_order))),
          port(port_network_order) {}
    Endpoint(const IPAddress& host, uint16_t port_network_order) noexcept
        : address(host), port(port_network_order) {}

    [[nodiscard]] bool is_ipv4() const noexcept {
        return address.family == IPAddressFamily::IPv4;
    }
    [[nodiscard]] bool is_ipv6() const noexcept {
        return address.family == IPAddressFamily::IPv6;
    }
    // Network-byte-order IPv4 address, or 0 for IPv6 endpoints.
    [[nodiscard]] uint32_t ipv4_network() const noexcept {
        return is_ipv4() ? htonl(address.ipv4_value()) : 0;
    }
    [[nodiscard]] bool unspecified() const noexcept {
        for (size_t i = 0; i < address.bit_width() / 8; ++i)
            if (address.bytes[i] != 0) return false;
        return true;
    }

    bool operator==(const Endpoint&) const = default;

    static Endpoint from_parts(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                               uint16_t port) {
        return Endpoint(htonl((static_cast<uint32_t>(a) << 24) |
                              (static_cast<uint32_t>(b) << 16) |
                              (static_cast<uint32_t>(c) << 8) |
                              static_cast<uint32_t>(d)),
                        htons(port));
    }
};

// "a.b.c.d:port" or "[v6]:port" with RFC 5952 zero compression.
[[nodiscard]] inline std::string endpoint_to_string(const Endpoint& endpoint) {
    std::string text;
    if (endpoint.is_ipv4()) {
        for (size_t i = 0; i < 4; ++i) {
            if (i) text += '.';
            text += std::to_string(endpoint.address.bytes[i]);
        }
    } else {
        std::array<uint16_t, 8> groups{};
        for (size_t i = 0; i < 8; ++i)
            groups[i] = static_cast<uint16_t>(
                (endpoint.address.bytes[i * 2] << 8) |
                endpoint.address.bytes[i * 2 + 1]);
        size_t best_start = 8, best_len = 0;
        for (size_t i = 0; i < 8;) {
            if (groups[i] != 0) { ++i; continue; }
            size_t j = i;
            while (j < 8 && groups[j] == 0) ++j;
            if (j - i > best_len && j - i >= 2) { best_start = i; best_len = j - i; }
            i = j;
        }
        text += '[';
        static constexpr char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < 8; ++i) {
            if (i == best_start) {
                text += "::";
                i += best_len - 1;
                continue;
            }
            if (!text.empty() && text.back() != ':' && text.back() != '[')
                text += ':';
            bool started = false;
            for (int shift = 12; shift >= 0; shift -= 4) {
                const unsigned nibble = (groups[i] >> shift) & 0xF;
                if (nibble || started || shift == 0) {
                    text += digits[nibble];
                    started = true;
                }
            }
        }
        text += ']';
    }
    text += ':';
    text += std::to_string(ntohs(endpoint.port));
    return text;
}

template <>
struct std::hash<Endpoint> {
    size_t operator()(const Endpoint& endpoint) const noexcept {
        uint64_t h = 1469598103934665603ull;
        const auto mix = [&h](uint8_t byte) {
            h = (h ^ byte) * 1099511628211ull;
        };
        mix(static_cast<uint8_t>(endpoint.address.family));
        for (const uint8_t byte : endpoint.address.bytes) mix(byte);
        mix(static_cast<uint8_t>(endpoint.port));
        mix(static_cast<uint8_t>(endpoint.port >> 8));
        return static_cast<size_t>(h);
    }
};
