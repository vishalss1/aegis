#include "aegis/file/transfer.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>

namespace {

char ascii_upper(char value) {
    if (value >= 'a' && value <= 'z')
        return static_cast<char>(value - ('a' - 'A'));
    return value;
}

bool ascii_iequals(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size())
        return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (ascii_upper(left[i]) != right[i])
            return false;
    }
    return true;
}

bool is_reserved_windows_name(std::string_view filename) noexcept {
    const size_t dot = filename.find('.');
    const std::string_view stem = filename.substr(0, dot);
    if (ascii_iequals(stem, "CON") || ascii_iequals(stem, "PRN") ||
        ascii_iequals(stem, "AUX") || ascii_iequals(stem, "NUL") ||
        ascii_iequals(stem, "CONIN$") || ascii_iequals(stem, "CONOUT$"))
        return true;
    if (stem.size() == 4 && stem[3] >= '1' && stem[3] <= '9') {
        const std::string_view prefix = stem.substr(0, 3);
        return ascii_iequals(prefix, "COM") || ascii_iequals(prefix, "LPT");
    }
    return false;
}

} // namespace

bool is_safe_file_name(std::string_view filename) noexcept {
    if (filename.empty() || filename.size() > FILE_TRANSFER_MAX_NAME_BYTES ||
        filename == "." || filename == ".." || filename.back() == '.' ||
        filename.back() == ' ' || is_reserved_windows_name(filename))
        return false;

    for (const unsigned char value : filename) {
        if (value < 32 || value == 127 || value == '"' || value == '*' ||
            value == '/' || value == ':' || value == '<' || value == '>' ||
            value == '?' || value == '\\' || value == '|')
            return false;
    }
    return true;
}

std::optional<std::string> sanitize_file_name(std::string_view path) {
    const size_t separator = path.find_last_of("/\\");
    const std::string_view filename = separator == std::string_view::npos
        ? path
        : path.substr(separator + 1);
    if (!is_safe_file_name(filename))
        return std::nullopt;
    return std::string(filename);
}

std::optional<uint32_t> file_chunk_size_for_overlay_mtu(
    size_t overlay_mtu) noexcept {
    const size_t payload_budget =
        (std::min)(overlay_mtu, SESSION_MAX_PAYLOAD_SIZE);
    if (payload_budget < FILE_CHUNK_FIXED_SIZE +
                             FILE_TRANSFER_MIN_CHUNK_SIZE)
        return std::nullopt;
    return static_cast<uint32_t>(payload_budget - FILE_CHUNK_FIXED_SIZE);
}

uint32_t file_transfer_chunk_count(
    uint64_t file_size, uint32_t chunk_size) noexcept {
    if (file_size > FILE_TRANSFER_MAX_FILE_SIZE ||
        chunk_size < FILE_TRANSFER_MIN_CHUNK_SIZE ||
        chunk_size > FILE_TRANSFER_MAX_CHUNK_SIZE)
        return 0;
    if (file_size == 0)
        return 1;
    return static_cast<uint32_t>(
        1 + ((file_size - 1) / chunk_size));
}

bool is_valid_file_header(const FileTransferHeader& header) noexcept {
    const uint32_t expected_chunks =
        file_transfer_chunk_count(header.file_size, header.chunk_size);
    return header.transfer_id != 0 && expected_chunks != 0 &&
           header.total_chunks == expected_chunks &&
           is_safe_file_name(header.filename);
}

bool is_valid_file_chunk(const FileTransferChunk& chunk) noexcept {
    return chunk.transfer_id != 0 &&
           chunk.chunk_index < FILE_TRANSFER_MAX_CHUNKS &&
           chunk.data.size() <= FILE_TRANSFER_MAX_CHUNK_SIZE;
}

bool is_valid_file_chunk_for_header(
    const FileTransferHeader& header,
    const FileTransferChunk& chunk) noexcept {
    if (!is_valid_file_header(header) || !is_valid_file_chunk(chunk) ||
        chunk.transfer_id != header.transfer_id ||
        chunk.chunk_index >= header.total_chunks)
        return false;

    size_t expected_size = header.chunk_size;
    if (chunk.chunk_index + 1 == header.total_chunks) {
        const uint64_t preceding_bytes =
            static_cast<uint64_t>(chunk.chunk_index) *
            header.chunk_size;
        expected_size = static_cast<size_t>(header.file_size - preceding_bytes);
    }
    return chunk.data.size() == expected_size;
}

std::optional<std::vector<uint8_t>> serialize_file_header(
    const FileTransferHeader& header) {
    if (!is_valid_file_header(header))
        return std::nullopt;

    std::vector<uint8_t> payload(
        FILE_HEADER_FIXED_SIZE + header.filename.size());
    WireWriter writer(payload);
    const auto filename = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(header.filename.data()),
        header.filename.size());
    if (!writer.write_u64(header.transfer_id) ||
        !writer.write_u64(header.file_size) ||
        !writer.write_u32(header.chunk_size) ||
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
    const auto chunk_size = reader.read_u32();
    const auto total_chunks = reader.read_u32();
    const auto filename_length = reader.read_u16();
    if (!transfer_id || !file_size || !chunk_size || !total_chunks ||
        !filename_length)
        return std::nullopt;
    const auto filename = reader.read_bytes(*filename_length);
    if (!filename || !reader.finished())
        return std::nullopt;

    FileTransferHeader header;
    header.transfer_id = *transfer_id;
    header.file_size = *file_size;
    header.chunk_size = *chunk_size;
    header.total_chunks = *total_chunks;
    header.filename.assign(
        reinterpret_cast<const char*>(filename->data()), filename->size());
    if (!is_valid_file_header(header))
        return std::nullopt;
    return header;
}

std::optional<std::vector<uint8_t>> serialize_file_chunk(
    const FileTransferChunk& chunk) {
    if (!is_valid_file_chunk(chunk))
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
    if (!is_valid_file_chunk(chunk))
        return std::nullopt;
    return chunk;
}
