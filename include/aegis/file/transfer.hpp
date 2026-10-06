#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/packet/header.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

inline constexpr size_t FILE_HEADER_FIXED_SIZE = 26;
inline constexpr size_t FILE_CHUNK_FIXED_SIZE = 16;
inline constexpr size_t FILE_TRANSFER_MAX_NAME_BYTES = 255;
inline constexpr uint32_t FILE_TRANSFER_MIN_CHUNK_SIZE = 512;
inline constexpr uint32_t FILE_TRANSFER_MAX_CHUNK_SIZE =
    static_cast<uint32_t>(SESSION_MAX_PAYLOAD_SIZE - FILE_CHUNK_FIXED_SIZE);
inline constexpr uint64_t FILE_TRANSFER_MAX_FILE_SIZE =
    1024ULL * 1024ULL * 1024ULL;
inline constexpr uint32_t FILE_TRANSFER_MAX_CHUNKS =
    static_cast<uint32_t>(
        (FILE_TRANSFER_MAX_FILE_SIZE + FILE_TRANSFER_MIN_CHUNK_SIZE - 1) /
        FILE_TRANSFER_MIN_CHUNK_SIZE);

struct FileTransferHeader {
    uint64_t transfer_id = 0;
    uint64_t file_size = 0;
    uint32_t chunk_size = 0;
    uint32_t total_chunks = 0;
    std::string filename;
};

struct FileTransferChunk {
    uint64_t transfer_id = 0;
    uint32_t chunk_index = 0;
    std::vector<uint8_t> data;
};

struct FileTransferKey {
    NodeId sender{};
    uint64_t transfer_id = 0;

    [[nodiscard]] bool operator<(const FileTransferKey& other) const noexcept {
        if (sender < other.sender)
            return true;
        if (other.sender < sender)
            return false;
        return transfer_id < other.transfer_id;
    }
};

enum class FileChunkReceipt {
    Accepted,
    Duplicate,
    OutOfRange
};

class FileChunkTracker {
public:
    [[nodiscard]] bool reset(uint32_t total_chunks);
    [[nodiscard]] FileChunkReceipt record(uint32_t chunk_index) noexcept;
    [[nodiscard]] bool received(uint32_t chunk_index) const noexcept;
    [[nodiscard]] bool complete() const noexcept;
    [[nodiscard]] uint32_t received_count() const noexcept {
        return received_count_;
    }
    [[nodiscard]] size_t total_chunks() const noexcept {
        return received_.size();
    }

private:
    std::vector<bool> received_;
    uint32_t received_count_ = 0;
};

// Local paths are reduced to one basename. Received names must already be a
// safe basename: traversal, Windows-invalid characters/device names, control
// bytes, and trailing spaces/dots are rejected rather than rewritten.
[[nodiscard]] bool is_safe_file_name(std::string_view filename) noexcept;
[[nodiscard]] std::optional<std::string> sanitize_file_name(
    std::string_view path);

[[nodiscard]] std::optional<uint32_t> file_chunk_size_for_overlay_mtu(
    size_t overlay_mtu) noexcept;
[[nodiscard]] uint32_t file_transfer_chunk_count(
    uint64_t file_size, uint32_t chunk_size) noexcept;
[[nodiscard]] bool is_valid_file_header(
    const FileTransferHeader& header) noexcept;
[[nodiscard]] bool is_valid_file_chunk(
    const FileTransferChunk& chunk) noexcept;
[[nodiscard]] bool is_valid_file_chunk_for_header(
    const FileTransferHeader& header,
    const FileTransferChunk& chunk) noexcept;

// File-transfer payload fields use canonical network byte order. Decoders
// require exact frame consumption and reject truncation or trailing bytes.
[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_file_header(
    const FileTransferHeader& header);
[[nodiscard]] std::optional<FileTransferHeader> deserialize_file_header(
    std::span<const uint8_t> payload);

[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_file_chunk(
    const FileTransferChunk& chunk);
[[nodiscard]] std::optional<FileTransferChunk> deserialize_file_chunk(
    std::span<const uint8_t> payload);
