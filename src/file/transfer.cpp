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

bool FileChunkTracker::reset(uint32_t total_chunks) {
    if (total_chunks == 0 || total_chunks > FILE_TRANSFER_MAX_CHUNKS)
        return false;
    received_.assign(total_chunks, false);
    received_count_ = 0;
    contiguous_received_ = 0;
    return true;
}

FileChunkReceipt FileChunkTracker::record(uint32_t chunk_index) noexcept {
    if (chunk_index >= received_.size())
        return FileChunkReceipt::OutOfRange;
    if (received_[chunk_index])
        return FileChunkReceipt::Duplicate;
    received_[chunk_index] = true;
    ++received_count_;
    while (contiguous_received_ < received_.size() &&
           received_[contiguous_received_])
        ++contiguous_received_;
    return FileChunkReceipt::Accepted;
}

bool FileChunkTracker::received(uint32_t chunk_index) const noexcept {
    return chunk_index < received_.size() && received_[chunk_index];
}

bool FileChunkTracker::complete() const noexcept {
    return !received_.empty() && received_count_ == received_.size();
}

std::vector<FileAckRange> FileChunkTracker::acknowledged_ranges(
    std::optional<uint32_t> focus, size_t maximum) const {
    std::vector<FileAckRange> ranges;
    if (maximum == 0)
        return ranges;
    if (contiguous_received_ > 0)
        ranges.push_back({0, contiguous_received_});
    if (!focus || *focus >= received_.size() || !received_[*focus] ||
        *focus < contiguous_received_ || ranges.size() >= maximum)
        return ranges;

    uint32_t first = *focus;
    while (first > contiguous_received_ && received_[first - 1])
        --first;
    uint32_t end = *focus + 1;
    while (end < received_.size() && received_[end])
        ++end;
    ranges.push_back({first, end - first});
    return ranges;
}

FileSendWindow::FileSendWindow(FileSendWindowConfig config)
    : config_(config), rto_(config.initial_rto) {}

bool FileSendWindow::reset(
    uint32_t total_chunks, ProtocolClock::time_point now) {
    if (total_chunks == 0 || total_chunks > FILE_TRANSFER_MAX_CHUNKS ||
        config_.window_size == 0 || config_.retry_limit == 0 ||
        config_.minimum_rto.count() <= 0 ||
        config_.initial_rto < config_.minimum_rto ||
        config_.initial_rto > config_.maximum_rto)
        return false;
    total_chunks_ = total_chunks;
    next_chunk_ = 0;
    acknowledged_count_ = 0;
    header_sent_ = false;
    header_received_ = false;
    failed_ = false;
    header_retransmissions_ = 0;
    header_sent_at_ = now;
    rto_ = config_.initial_rto;
    in_flight_.clear();
    return true;
}

FileSendAction FileSendWindow::poll(ProtocolClock::time_point now) {
    FileSendAction action;
    if (failed_ || complete() || total_chunks_ == 0)
        return action;

    if (!header_received_) {
        if (!header_sent_ || now - header_sent_at_ >= rto_) {
            if (header_sent_) {
                if (header_retransmissions_ >= config_.retry_limit) {
                    failed_ = true;
                    return action;
                }
                ++header_retransmissions_;
            }
            header_sent_ = true;
            header_sent_at_ = now;
            action.send_header = true;
        }
        return action;
    }

    for (auto& entry : in_flight_) {
        if (now - entry.second.sent_at < rto_)
            continue;
        if (entry.second.retransmissions >= config_.retry_limit) {
            failed_ = true;
            action.chunks.clear();
            return action;
        }
        ++entry.second.retransmissions;
        entry.second.sent_at = now;
        action.chunks.push_back(entry.first);
    }
    while (in_flight_.size() < config_.window_size &&
           next_chunk_ < total_chunks_) {
        in_flight_.emplace(next_chunk_, InFlightChunk{now, 0});
        action.chunks.push_back(next_chunk_);
        ++next_chunk_;
    }
    return action;
}

void FileSendWindow::acknowledge(
    const FileTransferAck& ack, ProtocolClock::time_point now) {
    if (failed_ || total_chunks_ == 0)
        return;
    if (ack.header_received && !header_received_) {
        if (header_sent_ && header_retransmissions_ == 0)
            observe_rtt(now - header_sent_at_);
        header_received_ = true;
    }

    for (auto it = in_flight_.begin(); it != in_flight_.end();) {
        bool acknowledged = false;
        for (const auto& range : ack.ranges) {
            const uint64_t end =
                static_cast<uint64_t>(range.first) + range.count;
            if (it->first >= range.first && it->first < end) {
                acknowledged = true;
                break;
            }
        }
        if (!acknowledged) {
            ++it;
            continue;
        }
        if (it->second.retransmissions == 0)
            observe_rtt(now - it->second.sent_at);
        ++acknowledged_count_;
        it = in_flight_.erase(it);
    }
}

bool FileSendWindow::complete() const noexcept {
    return total_chunks_ != 0 && acknowledged_count_ == total_chunks_;
}

void FileSendWindow::observe_rtt(
    std::chrono::steady_clock::duration sample) noexcept {
    auto measured = std::chrono::duration_cast<std::chrono::milliseconds>(
        sample) * 2;
    if (measured < config_.minimum_rto)
        measured = config_.minimum_rto;
    if (measured > config_.maximum_rto)
        measured = config_.maximum_rto;
    rto_ = measured;
}

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

std::optional<std::vector<uint8_t>> serialize_file_ack(
    const FileTransferAck& ack) {
    if (ack.transfer_id == 0 || ack.ranges.size() > FILE_ACK_MAX_RANGES)
        return std::nullopt;
    uint64_t previous_end = 0;
    for (const auto& range : ack.ranges) {
        const uint64_t end =
            static_cast<uint64_t>(range.first) + range.count;
        if (range.count == 0 || end > FILE_TRANSFER_MAX_CHUNKS ||
            range.first < previous_end)
            return std::nullopt;
        previous_end = end;
    }

    std::vector<uint8_t> payload(
        FILE_ACK_FIXED_SIZE + ack.ranges.size() * FILE_ACK_RANGE_SIZE);
    WireWriter writer(payload);
    if (!writer.write_u64(ack.transfer_id) ||
        !writer.write_u8(ack.header_received ? 1 : 0) ||
        !writer.write_u8(0) ||
        !writer.write_u16(static_cast<uint16_t>(ack.ranges.size())))
        return std::nullopt;
    for (const auto& range : ack.ranges) {
        if (!writer.write_u32(range.first) || !writer.write_u32(range.count))
            return std::nullopt;
    }
    if (!writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<FileTransferAck> deserialize_file_ack(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto transfer_id = reader.read_u64();
    const auto flags = reader.read_u8();
    const auto reserved = reader.read_u8();
    const auto range_count = reader.read_u16();
    if (!transfer_id || !flags || !reserved || !range_count ||
        *transfer_id == 0 || (*flags & 0xFEu) != 0 || *reserved != 0 ||
        *range_count > FILE_ACK_MAX_RANGES)
        return std::nullopt;

    FileTransferAck ack;
    ack.transfer_id = *transfer_id;
    ack.header_received = (*flags & 0x01u) != 0;
    ack.ranges.reserve(*range_count);
    uint64_t previous_end = 0;
    for (uint16_t i = 0; i < *range_count; ++i) {
        const auto first = reader.read_u32();
        const auto count = reader.read_u32();
        if (!first || !count)
            return std::nullopt;
        const uint64_t end = static_cast<uint64_t>(*first) + *count;
        if (*count == 0 || end > FILE_TRANSFER_MAX_CHUNKS ||
            *first < previous_end)
            return std::nullopt;
        ack.ranges.push_back({*first, *count});
        previous_end = end;
    }
    if (!reader.finished())
        return std::nullopt;
    return ack;
}
