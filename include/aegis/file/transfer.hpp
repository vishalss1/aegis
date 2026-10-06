#pragma once

#include "aegis/identity/identity.hpp"
#include "aegis/crypto/primitives.hpp"
#include "aegis/packet/header.hpp"
#include "aegis/protocol/sources.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

inline constexpr size_t FILE_HEADER_FIXED_SIZE = 58;
inline constexpr size_t FILE_CHUNK_FIXED_SIZE = 16;
inline constexpr size_t FILE_ACK_FIXED_SIZE = 12;
inline constexpr size_t FILE_ACK_RANGE_SIZE = 8;
inline constexpr size_t FILE_CANCEL_SIZE = 12;
inline constexpr size_t FILE_ACK_MAX_RANGES = 32;
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
inline constexpr size_t FILE_TRANSFER_MAX_ACTIVE_PER_PEER = 4;
inline constexpr size_t FILE_TRANSFER_MAX_ACTIVE_GLOBAL = 32;
inline constexpr uint64_t FILE_TRANSFER_MAX_RESERVED_PER_PEER =
    2ULL * FILE_TRANSFER_MAX_FILE_SIZE;
inline constexpr uint64_t FILE_TRANSFER_MAX_RESERVED_GLOBAL =
    8ULL * FILE_TRANSFER_MAX_FILE_SIZE;
inline constexpr auto FILE_TRANSFER_IDLE_TIMEOUT = std::chrono::minutes(5);

struct FileTransferHeader {
    uint64_t transfer_id = 0;
    uint64_t file_size = 0;
    uint32_t chunk_size = 0;
    uint32_t total_chunks = 0;
    CryptoHash content_hash{};
    std::string filename;
};

struct FileTransferChunk {
    uint64_t transfer_id = 0;
    uint32_t chunk_index = 0;
    std::vector<uint8_t> data;
};

struct FileAckRange {
    uint32_t first = 0;
    uint32_t count = 0;
};

struct FileTransferAck {
    uint64_t transfer_id = 0;
    bool header_received = false;
    std::vector<FileAckRange> ranges;
};

enum class FileCancelReason : uint8_t {
    SenderCancelled = 1,
    RetryLimit = 2,
    TimedOut = 3,
    Capacity = 4
};

struct FileTransferCancel {
    uint64_t transfer_id = 0;
    FileCancelReason reason = FileCancelReason::SenderCancelled;
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
    [[nodiscard]] bool remove(uint32_t chunk_index) noexcept;
    [[nodiscard]] bool received(uint32_t chunk_index) const noexcept;
    [[nodiscard]] bool complete() const noexcept;
    [[nodiscard]] uint32_t received_count() const noexcept {
        return received_count_;
    }
    [[nodiscard]] size_t total_chunks() const noexcept {
        return received_.size();
    }
    [[nodiscard]] std::vector<FileAckRange> acknowledged_ranges(
        std::optional<uint32_t> focus = std::nullopt,
        size_t maximum = FILE_ACK_MAX_RANGES) const;

private:
    std::vector<bool> received_;
    uint32_t received_count_ = 0;
    uint32_t contiguous_received_ = 0;
};

enum class FileCommitResult {
    Committed,
    IoError,
    SizeMismatch,
    DigestMismatch,
    RenameFailed
};

[[nodiscard]] std::optional<CryptoHash> hash_file_sha256(
    const std::string& path, uint64_t expected_size);
[[nodiscard]] std::string file_transfer_part_name(
    const NodeId& sender, uint64_t transfer_id);
[[nodiscard]] FileCommitResult verify_and_commit_file(
    const std::string& part_path, const std::string& final_path,
    uint64_t expected_size, const CryptoHash& expected_hash);

struct FileSendAction {
    bool send_header = false;
    std::vector<uint32_t> chunks;
};

struct FileSendWindowConfig {
    size_t window_size = 32;
    uint32_t retry_limit = 5;
    std::chrono::milliseconds initial_rto{250};
    std::chrono::milliseconds minimum_rto{100};
    std::chrono::milliseconds maximum_rto{2000};
};

class FileSendWindow {
public:
    explicit FileSendWindow(FileSendWindowConfig config = {});

    [[nodiscard]] bool reset(
        uint32_t total_chunks, ProtocolClock::time_point now);
    [[nodiscard]] FileSendAction poll(ProtocolClock::time_point now);
    void acknowledge(
        const FileTransferAck& ack, ProtocolClock::time_point now);
    void cancel() noexcept { failed_ = true; }

    [[nodiscard]] bool complete() const noexcept;
    [[nodiscard]] bool failed() const noexcept { return failed_; }
    [[nodiscard]] uint32_t acknowledged_count() const noexcept {
        return acknowledged_count_;
    }
    [[nodiscard]] std::chrono::milliseconds rto() const noexcept {
        return rto_;
    }

private:
    struct InFlightChunk {
        ProtocolClock::time_point sent_at{};
        uint32_t retransmissions = 0;
    };

    FileSendWindowConfig config_;
    uint32_t total_chunks_ = 0;
    uint32_t next_chunk_ = 0;
    uint32_t acknowledged_count_ = 0;
    bool header_sent_ = false;
    bool header_received_ = false;
    bool failed_ = false;
    uint32_t header_retransmissions_ = 0;
    ProtocolClock::time_point header_sent_at_{};
    std::chrono::milliseconds rto_{};
    std::map<uint32_t, InFlightChunk> in_flight_;
    std::vector<bool> acknowledged_;

    void observe_rtt(std::chrono::steady_clock::duration sample) noexcept;
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

[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_file_ack(
    const FileTransferAck& ack);
[[nodiscard]] std::optional<FileTransferAck> deserialize_file_ack(
    std::span<const uint8_t> payload);

[[nodiscard]] std::optional<std::vector<uint8_t>> serialize_file_cancel(
    const FileTransferCancel& cancel);
[[nodiscard]] std::optional<FileTransferCancel> deserialize_file_cancel(
    std::span<const uint8_t> payload);

[[nodiscard]] bool file_transfer_admission_allowed(
    size_t peer_count, uint64_t peer_bytes, size_t global_count,
    uint64_t global_bytes, uint64_t requested_bytes) noexcept;
[[nodiscard]] bool file_transfer_idle_expired(
    ProtocolClock::time_point last_activity,
    ProtocolClock::time_point now) noexcept;
