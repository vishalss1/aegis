#pragma once

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

enum class IPAddressFamily : uint8_t { IPv4 = 4, IPv6 = 6 };

struct IPAddress {
    IPAddressFamily family = IPAddressFamily::IPv4;
    std::array<uint8_t, 16> bytes{};

    IPAddress() = default;
    IPAddress(uint32_t network_order) noexcept {
        bytes[0] = static_cast<uint8_t>(network_order >> 24);
        bytes[1] = static_cast<uint8_t>(network_order >> 16);
        bytes[2] = static_cast<uint8_t>(network_order >> 8);
        bytes[3] = static_cast<uint8_t>(network_order);
    }

    [[nodiscard]] static IPAddress from_ipv4(uint32_t network_order) noexcept {
        IPAddress address;
        address.bytes[0] = static_cast<uint8_t>(network_order >> 24);
        address.bytes[1] = static_cast<uint8_t>(network_order >> 16);
        address.bytes[2] = static_cast<uint8_t>(network_order >> 8);
        address.bytes[3] = static_cast<uint8_t>(network_order);
        return address;
    }

    [[nodiscard]] static IPAddress from_ipv6(
        const std::array<uint8_t, 16>& value) noexcept {
        IPAddress address;
        address.family = IPAddressFamily::IPv6;
        address.bytes = value;
        return address;
    }

    [[nodiscard]] constexpr bool valid_family() const noexcept {
        return family == IPAddressFamily::IPv4 ||
               family == IPAddressFamily::IPv6;
    }

    [[nodiscard]] constexpr size_t bit_width() const noexcept {
        return family == IPAddressFamily::IPv4 ? 32 :
               family == IPAddressFamily::IPv6 ? 128 : 0;
    }

    [[nodiscard]] uint32_t ipv4_value() const noexcept {
        if (family != IPAddressFamily::IPv4) return 0;
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) |
               static_cast<uint32_t>(bytes[3]);
    }

    [[nodiscard]] static std::optional<IPAddress> parse(
        std::string_view text) noexcept {
        if (text.empty()) return std::nullopt;
        if (text.find(':') == std::string_view::npos) {
            if (text.back() == '.') return std::nullopt;
            std::array<uint8_t, 4> octets{};
            size_t count = 0;
            size_t start = 0;
            while (start < text.size()) {
                const size_t end = text.find('.', start);
                const size_t stop = end == std::string_view::npos
                    ? text.size() : end;
                if (stop == start || stop - start > 3 || count == octets.size())
                    return std::nullopt;
                unsigned value = 0;
                for (size_t i = start; i < stop; ++i) {
                    if (text[i] < '0' || text[i] > '9') return std::nullopt;
                    value = value * 10 + static_cast<unsigned>(text[i] - '0');
                }
                if (value > 255) return std::nullopt;
                octets[count++] = static_cast<uint8_t>(value);
                if (end == std::string_view::npos) break;
                start = end + 1;
            }
            if (count != 4) return std::nullopt;
            IPAddress address;
            std::copy(octets.begin(), octets.end(), address.bytes.begin());
            return address;
        }
        const auto compression = text.find("::");
        if (text.back() == ':' &&
            (compression == std::string_view::npos ||
             text.substr(text.size() - 2) != "::"))
            return std::nullopt;
        if (compression != std::string_view::npos &&
            text.find("::", compression + 2) != std::string_view::npos)
            return std::nullopt;

        const auto parse_side = [](std::string_view side,
                                   std::array<uint16_t, 8>& groups,
                                   size_t& count) noexcept {
            count = 0;
            if (side.empty()) return true;
            size_t start = 0;
            while (start < side.size()) {
                const size_t end = side.find(':', start);
                const size_t stop = end == std::string_view::npos
                    ? side.size() : end;
                if (stop == start || stop - start > 4 || count == groups.size())
                    return false;
                uint16_t value = 0;
                for (size_t i = start; i < stop; ++i) {
                    const char ch = side[i];
                    uint8_t digit;
                    if (ch >= '0' && ch <= '9') digit = ch - '0';
                    else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
                    else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
                    else return false;
                    value = static_cast<uint16_t>((value << 4) | digit);
                }
                groups[count++] = value;
                if (end == std::string_view::npos) break;
                start = end + 1;
            }
            return true;
        };

        std::array<uint16_t, 8> groups{};
        size_t left_count = 0;
        size_t right_count = 0;
        if (compression == std::string_view::npos) {
            if (!parse_side(text, groups, left_count) || left_count != 8)
                return std::nullopt;
        } else {
            std::array<uint16_t, 8> left{};
            std::array<uint16_t, 8> right{};
            if (!parse_side(text.substr(0, compression), left, left_count) ||
                !parse_side(text.substr(compression + 2), right, right_count) ||
                left_count + right_count >= 8)
                return std::nullopt;
            for (size_t i = 0; i < left_count; ++i) groups[i] = left[i];
            for (size_t i = 0; i < right_count; ++i)
                groups[8 - right_count + i] = right[i];
        }

        IPAddress address;
        address.family = IPAddressFamily::IPv6;
        for (size_t i = 0; i < groups.size(); ++i) {
            address.bytes[i * 2] = static_cast<uint8_t>(groups[i] >> 8);
            address.bytes[i * 2 + 1] = static_cast<uint8_t>(groups[i]);
        }
        return address;
    }

    [[nodiscard]] bool operator==(const IPAddress&) const = default;
    [[nodiscard]] auto operator<=>(const IPAddress&) const = default;
    [[nodiscard]] bool operator==(uint32_t ipv4) const noexcept {
        return family == IPAddressFamily::IPv4 && *this == from_ipv4(ipv4);
    }
};

struct IPPrefix {
    IPAddress address{};
    uint8_t length = 0;

    IPPrefix() = default;
    IPPrefix(IPAddress network, uint8_t prefix_length) noexcept
        : address(network), length(prefix_length) { canonicalize(); }
    IPPrefix(uint32_t ipv4_network, uint8_t prefix_length) noexcept
        : IPPrefix(IPAddress::from_ipv4(ipv4_network), prefix_length) {}

    [[nodiscard]] static std::optional<IPPrefix> parse(
        std::string_view text) noexcept {
        const size_t slash = text.find('/');
        if (slash == std::string_view::npos || slash == 0 ||
            slash + 1 == text.size() ||
            text.find('/', slash + 1) != std::string_view::npos)
            return std::nullopt;
        const auto address = IPAddress::parse(text.substr(0, slash));
        if (!address) return std::nullopt;
        unsigned length = 0;
        for (size_t i = slash + 1; i < text.size(); ++i) {
            const char ch = text[i];
            if (ch < '0' || ch > '9') return std::nullopt;
            length = length * 10 + static_cast<unsigned>(ch - '0');
            if (length > 128) return std::nullopt;
        }
        if (length > address->bit_width()) return std::nullopt;
        return IPPrefix(*address, static_cast<uint8_t>(length));
    }

    [[nodiscard]] bool valid() const noexcept {
        return address.valid_family() && length <= address.bit_width();
    }

    void canonicalize() noexcept {
        const size_t width = address.bit_width();
        if (length > width) return;
        const size_t full_bytes = length / 8;
        const size_t remaining_bits = length % 8;
        if (remaining_bits != 0) {
            address.bytes[full_bytes] &= static_cast<uint8_t>(
                0xffu << (8 - remaining_bits));
        }
        const size_t zero_from = full_bytes + (remaining_bits != 0 ? 1 : 0);
        for (size_t i = zero_from; i < width / 8; ++i)
            address.bytes[i] = 0;
        for (size_t i = width / 8; i < address.bytes.size(); ++i)
            address.bytes[i] = 0;
    }

    [[nodiscard]] bool contains(const IPAddress& candidate) const noexcept {
        if (!valid() || candidate.family != address.family) return false;
        const size_t full_bytes = length / 8;
        const size_t remaining_bits = length % 8;
        for (size_t i = 0; i < full_bytes; ++i)
            if (address.bytes[i] != candidate.bytes[i]) return false;
        if (remaining_bits != 0) {
            const uint8_t mask = static_cast<uint8_t>(
                0xffu << (8 - remaining_bits));
            if ((address.bytes[full_bytes] & mask) !=
                (candidate.bytes[full_bytes] & mask)) return false;
        }
        return true;
    }

    [[nodiscard]] bool operator==(const IPPrefix&) const = default;
};

// A host address assigned to an interface; unlike IPPrefix, this preserves
// host bits while carrying the interface's on-link prefix length.
struct IPInterfaceAddress {
    IPAddress address{};
    uint8_t prefix_length = 0;

    [[nodiscard]] bool valid() const noexcept {
        return address.valid_family() &&
               prefix_length <= address.bit_width();
    }

    [[nodiscard]] static std::optional<IPInterfaceAddress> parse(
        std::string_view text) noexcept {
        const size_t slash = text.find('/');
        if (slash == std::string_view::npos || slash == 0 ||
            slash + 1 == text.size() ||
            text.find('/', slash + 1) != std::string_view::npos)
            return std::nullopt;
        const auto parsed_address = IPAddress::parse(text.substr(0, slash));
        if (!parsed_address) return std::nullopt;
        unsigned length = 0;
        for (size_t i = slash + 1; i < text.size(); ++i) {
            const char ch = text[i];
            if (ch < '0' || ch > '9') return std::nullopt;
            length = length * 10 + static_cast<unsigned>(ch - '0');
            if (length > parsed_address->bit_width()) return std::nullopt;
        }
        return IPInterfaceAddress{*parsed_address,
                                  static_cast<uint8_t>(length)};
    }
};
