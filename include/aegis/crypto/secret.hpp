#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <openssl/crypto.h>

// Fixed-size storage for key material. Every owned copy is cleansed when it is
// destroyed or overwritten; moving also clears the source immediately.
template <size_t Size>
class SecretBytes {
public:
    using value_type = uint8_t;
    using iterator = typename std::array<uint8_t, Size>::iterator;
    using const_iterator = typename std::array<uint8_t, Size>::const_iterator;

    SecretBytes() = default;

    SecretBytes(const SecretBytes& other) : bytes_(other.bytes_) {}

    SecretBytes& operator=(const SecretBytes& other) {
        if (this != &other) {
            cleanse();
            bytes_ = other.bytes_;
        }
        return *this;
    }

    SecretBytes(SecretBytes&& other) noexcept : bytes_(other.bytes_) {
        other.cleanse();
    }

    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            cleanse();
            bytes_ = other.bytes_;
            other.cleanse();
        }
        return *this;
    }

    ~SecretBytes() { cleanse(); }

    [[nodiscard]] uint8_t* data() noexcept { return bytes_.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return bytes_.data(); }
    [[nodiscard]] constexpr size_t size() const noexcept { return Size; }
    [[nodiscard]] constexpr bool empty() const noexcept { return Size == 0; }

    iterator begin() noexcept { return bytes_.begin(); }
    const_iterator begin() const noexcept { return bytes_.begin(); }
    const_iterator cbegin() const noexcept { return bytes_.cbegin(); }
    iterator end() noexcept { return bytes_.end(); }
    const_iterator end() const noexcept { return bytes_.end(); }
    const_iterator cend() const noexcept { return bytes_.cend(); }

    uint8_t& operator[](size_t index) noexcept { return bytes_[index]; }
    const uint8_t& operator[](size_t index) const noexcept {
        return bytes_[index];
    }

    void fill(uint8_t value) noexcept { bytes_.fill(value); }
    void clear() noexcept { cleanse(); }

    friend bool operator==(
        const SecretBytes& left, const SecretBytes& right) noexcept {
        if constexpr (Size == 0)
            return true;
        return CRYPTO_memcmp(left.data(), right.data(), Size) == 0;
    }

private:
    void cleanse() noexcept { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

    std::array<uint8_t, Size> bytes_{};
};
