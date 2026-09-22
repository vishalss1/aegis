#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

// Bounded, allocation-free helpers for protocol fields. Multi-byte integers
// are encoded in network byte order. A failed operation leaves both the cursor
// and the destination buffer unchanged.
class WireReader {
public:
    explicit WireReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] std::optional<uint8_t> read_u8() {
        const auto bytes = read_bytes(1);
        if (!bytes)
            return std::nullopt;
        return (*bytes)[0];
    }

    [[nodiscard]] std::optional<uint16_t> read_u16() {
        const auto bytes = read_bytes(2);
        if (!bytes)
            return std::nullopt;
        return static_cast<uint16_t>(
            (static_cast<uint16_t>((*bytes)[0]) << 8) |
            static_cast<uint16_t>((*bytes)[1]));
    }

    [[nodiscard]] std::optional<uint32_t> read_u32() {
        const auto bytes = read_bytes(4);
        if (!bytes)
            return std::nullopt;
        return (static_cast<uint32_t>((*bytes)[0]) << 24) |
               (static_cast<uint32_t>((*bytes)[1]) << 16) |
               (static_cast<uint32_t>((*bytes)[2]) << 8) |
               static_cast<uint32_t>((*bytes)[3]);
    }

    [[nodiscard]] std::optional<uint64_t> read_u64() {
        const auto bytes = read_bytes(8);
        if (!bytes)
            return std::nullopt;

        uint64_t value = 0;
        for (const uint8_t byte : *bytes)
            value = (value << 8) | static_cast<uint64_t>(byte);
        return value;
    }

    [[nodiscard]] std::optional<std::span<const uint8_t>> read_bytes(
        size_t count) {
        if (count > remaining())
            return std::nullopt;
        const auto result = bytes_.subspan(offset_, count);
        offset_ += count;
        return result;
    }

    [[nodiscard]] size_t position() const { return offset_; }
    [[nodiscard]] size_t remaining() const { return bytes_.size() - offset_; }
    [[nodiscard]] bool finished() const { return offset_ == bytes_.size(); }

private:
    std::span<const uint8_t> bytes_;
    size_t offset_ = 0;
};

class WireWriter {
public:
    explicit WireWriter(std::span<uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool write_u8(uint8_t value) {
        return write_bytes(std::span<const uint8_t>(&value, 1));
    }

    [[nodiscard]] bool write_u16(uint16_t value) {
        const uint8_t encoded[] = {
            static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value)
        };
        return write_bytes(encoded);
    }

    [[nodiscard]] bool write_u32(uint32_t value) {
        const uint8_t encoded[] = {
            static_cast<uint8_t>(value >> 24),
            static_cast<uint8_t>(value >> 16),
            static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value)
        };
        return write_bytes(encoded);
    }

    [[nodiscard]] bool write_u64(uint64_t value) {
        const uint8_t encoded[] = {
            static_cast<uint8_t>(value >> 56),
            static_cast<uint8_t>(value >> 48),
            static_cast<uint8_t>(value >> 40),
            static_cast<uint8_t>(value >> 32),
            static_cast<uint8_t>(value >> 24),
            static_cast<uint8_t>(value >> 16),
            static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value)
        };
        return write_bytes(encoded);
    }

    [[nodiscard]] bool write_bytes(std::span<const uint8_t> value) {
        if (value.size() > remaining())
            return false;
        auto destination = bytes_.subspan(offset_, value.size());
        std::copy(value.begin(), value.end(), destination.begin());
        offset_ += value.size();
        return true;
    }

    [[nodiscard]] size_t position() const { return offset_; }
    [[nodiscard]] size_t remaining() const { return bytes_.size() - offset_; }
    [[nodiscard]] bool finished() const { return offset_ == bytes_.size(); }
    [[nodiscard]] std::span<const uint8_t> written() const {
        return bytes_.first(offset_);
    }

private:
    std::span<uint8_t> bytes_;
    size_t offset_ = 0;
};
