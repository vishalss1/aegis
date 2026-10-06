#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

inline constexpr size_t FILE_HEADER_FIXED_SIZE = 22;
inline constexpr size_t FILE_CHUNK_FIXED_SIZE = 16;

struct FileTransferHeader {
    uint64_t transfer_id = 0;
    uint64_t file_size = 0;
    uint32_t total_chunks = 0;
    std::string filename;
};

struct FileTransferChunk {
    uint64_t transfer_id = 0;
    uint32_t chunk_index = 0;
    std::vector<uint8_t> data;
};

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
