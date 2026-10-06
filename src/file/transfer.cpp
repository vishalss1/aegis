#include "aegis/file/transfer.hpp"
#include "aegis/protocol/wire.hpp"
#include <limits>

std::optional<std::vector<uint8_t>> serialize_file_header(
    const FileTransferHeader& header) {
    if (header.filename.size() > std::numeric_limits<uint16_t>::max())
        return std::nullopt;

    std::vector<uint8_t> payload(
        FILE_HEADER_FIXED_SIZE + header.filename.size());
    WireWriter writer(payload);
    const auto filename = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(header.filename.data()),
        header.filename.size());
    if (!writer.write_u64(header.transfer_id) ||
        !writer.write_u64(header.file_size) ||
        !writer.write_u32(header.total_chunks) ||
        !writer.write_u16(static_cast<uint16_t>(header.filename.size())) ||
        !writer.write_bytes(filename) || !writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<FileTransferHeader> deserialize_file_header(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto transfer_id = reader.read_u64();
    const auto file_size = reader.read_u64();
    const auto total_chunks = reader.read_u32();
    const auto filename_length = reader.read_u16();
    if (!transfer_id || !file_size || !total_chunks || !filename_length)
        return std::nullopt;
    const auto filename = reader.read_bytes(*filename_length);
    if (!filename || !reader.finished())
        return std::nullopt;

    FileTransferHeader header;
    header.transfer_id = *transfer_id;
    header.file_size = *file_size;
    header.total_chunks = *total_chunks;
    header.filename.assign(
        reinterpret_cast<const char*>(filename->data()), filename->size());
    return header;
}

std::optional<std::vector<uint8_t>> serialize_file_chunk(
    const FileTransferChunk& chunk) {
    if (chunk.data.size() > std::numeric_limits<uint32_t>::max())
        return std::nullopt;

    std::vector<uint8_t> payload(FILE_CHUNK_FIXED_SIZE + chunk.data.size());
    WireWriter writer(payload);
    if (!writer.write_u64(chunk.transfer_id) ||
        !writer.write_u32(chunk.chunk_index) ||
        !writer.write_u32(static_cast<uint32_t>(chunk.data.size())) ||
        !writer.write_bytes(chunk.data) || !writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<FileTransferChunk> deserialize_file_chunk(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto transfer_id = reader.read_u64();
    const auto chunk_index = reader.read_u32();
    const auto data_length = reader.read_u32();
    if (!transfer_id || !chunk_index || !data_length)
        return std::nullopt;
    const auto data = reader.read_bytes(*data_length);
    if (!data || !reader.finished())
        return std::nullopt;

    FileTransferChunk chunk;
    chunk.transfer_id = *transfer_id;
    chunk.chunk_index = *chunk_index;
    chunk.data.assign(data->begin(), data->end());
    return chunk;
}
