#include "aegis/file/transfer.hpp"
#include "aegis/packet/mtu.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

static int tests = 0;
static int passed = 0;

class ManualClock final : public ProtocolClock {
public:
    [[nodiscard]] time_point now() const noexcept override { return now_; }
    void advance(std::chrono::milliseconds duration) { now_ += duration; }

private:
    time_point now_{};
};

#define CHECK(cond) do { \
    tests++; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("--- file transfer framing tests ---\n");

    CryptoHash header_hash{};
    for (size_t i = 0; i < header_hash.size(); ++i)
        header_hash[i] = static_cast<uint8_t>(i);
    const FileTransferHeader header{
        0x0102030405060708ULL,
        902,
        900,
        2,
        header_hash,
        "report.bin"
    };
    const auto encoded_header = serialize_file_header(header);
    CHECK(encoded_header.has_value());
    CHECK(encoded_header && encoded_header->size() ==
          FILE_HEADER_FIXED_SIZE + header.filename.size());
    CHECK(encoded_header && (*encoded_header)[0] == 0x01 &&
          (*encoded_header)[7] == 0x08 && (*encoded_header)[14] == 0x03 &&
          (*encoded_header)[15] == 0x86 && (*encoded_header)[18] == 0x03 &&
          (*encoded_header)[19] == 0x84 && (*encoded_header)[22] == 0x00 &&
          (*encoded_header)[23] == 0x02 && (*encoded_header)[24] == 0x00 &&
          (*encoded_header)[55] == 0x1f && (*encoded_header)[56] == 0x00 &&
          (*encoded_header)[57] == header.filename.size());

    const auto decoded_header = encoded_header
        ? deserialize_file_header(*encoded_header)
        : std::nullopt;
    CHECK(decoded_header.has_value());
    CHECK(decoded_header && decoded_header->transfer_id == header.transfer_id);
    CHECK(decoded_header && decoded_header->file_size == header.file_size);
    CHECK(decoded_header && decoded_header->chunk_size == header.chunk_size);
    CHECK(decoded_header && decoded_header->total_chunks == header.total_chunks);
    CHECK(decoded_header && decoded_header->content_hash == header.content_hash);
    CHECK(decoded_header && decoded_header->filename == header.filename);

    if (encoded_header) {
        auto truncated = *encoded_header;
        truncated.pop_back();
        CHECK(!deserialize_file_header(truncated).has_value());

        auto trailing = *encoded_header;
        trailing.push_back(0);
        CHECK(!deserialize_file_header(trailing).has_value());

        auto oversized_name = *encoded_header;
        oversized_name[56] = 0x7f;
        oversized_name[57] = 0xff;
        CHECK(!deserialize_file_header(oversized_name).has_value());

        auto traversal_name = *encoded_header;
        const std::string traversal = "../bad.bin";
        std::copy(traversal.begin(), traversal.end(),
                  traversal_name.begin() + FILE_HEADER_FIXED_SIZE);
        CHECK(!deserialize_file_header(traversal_name).has_value());
    }

    FileTransferHeader long_name;
    long_name.transfer_id = 1;
    long_name.chunk_size = FILE_TRANSFER_MIN_CHUNK_SIZE;
    long_name.total_chunks = 1;
    long_name.filename.assign(FILE_TRANSFER_MAX_NAME_BYTES + 1, 'a');
    CHECK(!serialize_file_header(long_name).has_value());

    CHECK(is_safe_file_name("report.txt"));
    CHECK(!is_safe_file_name("../report.txt"));
    CHECK(!is_safe_file_name("folder\\report.txt"));
    CHECK(!is_safe_file_name("CON.txt"));
    CHECK(!is_safe_file_name("lpt9"));
    CHECK(!is_safe_file_name("report.txt."));
    CHECK(!is_safe_file_name(std::string("bad\0name", 8)));
    const auto basename = sanitize_file_name("C:\\safe\\report.txt");
    CHECK(basename && *basename == "report.txt");
    CHECK(!sanitize_file_name("C:\\safe\\NUL.txt").has_value());

    FileTransferHeader invalid_header = header;
    invalid_header.transfer_id = 0;
    CHECK(!is_valid_file_header(invalid_header));
    invalid_header = header;
    invalid_header.total_chunks = 3;
    CHECK(!is_valid_file_header(invalid_header));
    invalid_header = header;
    invalid_header.file_size = FILE_TRANSFER_MAX_FILE_SIZE + 1;
    CHECK(!is_valid_file_header(invalid_header));
    invalid_header = header;
    invalid_header.chunk_size = FILE_TRANSFER_MIN_CHUNK_SIZE - 1;
    CHECK(!is_valid_file_header(invalid_header));
    invalid_header = header;
    invalid_header.chunk_size = FILE_TRANSFER_MAX_CHUNK_SIZE + 1;
    CHECK(!is_valid_file_header(invalid_header));
    CHECK(file_transfer_chunk_count(0, FILE_TRANSFER_MIN_CHUNK_SIZE) == 1);
    CHECK(file_transfer_chunk_count(
              FILE_TRANSFER_MAX_FILE_SIZE,
              FILE_TRANSFER_MIN_CHUNK_SIZE) ==
          FILE_TRANSFER_MAX_CHUNKS);
    CHECK(file_transfer_chunk_count(
              FILE_TRANSFER_MAX_FILE_SIZE + 1,
              FILE_TRANSFER_MIN_CHUNK_SIZE) == 0);
    CHECK(file_transfer_chunk_count(1, FILE_TRANSFER_MIN_CHUNK_SIZE - 1) == 0);

    const auto direct_mtu = safe_overlay_mtu(1500, DIRECT_ROUTE_DEPTH);
    const auto relayed_mtu = safe_overlay_mtu(1500, ONION_MAX_HOPS);
    CHECK(direct_mtu && *direct_mtu == 1428);
    CHECK(relayed_mtu && *relayed_mtu == 916);
    CHECK(direct_mtu && file_chunk_size_for_overlay_mtu(*direct_mtu) == 1412);
    CHECK(relayed_mtu && file_chunk_size_for_overlay_mtu(*relayed_mtu) == 900);
    CHECK(file_chunk_size_for_overlay_mtu(576) == 560);
    CHECK(file_chunk_size_for_overlay_mtu(527) == std::nullopt);
    CHECK(file_chunk_size_for_overlay_mtu(65535) ==
          FILE_TRANSFER_MAX_CHUNK_SIZE);
    for (size_t depth = DIRECT_ROUTE_DEPTH; depth <= ONION_MAX_HOPS; ++depth) {
        const auto mtu = safe_overlay_mtu(DEFAULT_UNDERLAY_MTU, depth);
        const auto capacity = mtu
            ? file_chunk_size_for_overlay_mtu(*mtu)
            : std::nullopt;
        CHECK(mtu && capacity &&
              static_cast<size_t>(*capacity) + FILE_CHUNK_FIXED_SIZE <= *mtu &&
              static_cast<size_t>(*capacity) + FILE_CHUNK_FIXED_SIZE <=
                  SESSION_MAX_PAYLOAD_SIZE);
    }

    const FileTransferChunk chunk{
        0x3132333435363738ULL,
        1,
        {0xde, 0xad, 0xbe, 0xef}
    };
    const auto encoded_chunk = serialize_file_chunk(chunk);
    CHECK(encoded_chunk.has_value());
    CHECK(encoded_chunk && encoded_chunk->size() ==
          FILE_CHUNK_FIXED_SIZE + chunk.data.size());
    CHECK(encoded_chunk && (*encoded_chunk)[0] == 0x31 &&
          (*encoded_chunk)[7] == 0x38 && (*encoded_chunk)[8] == 0x00 &&
          (*encoded_chunk)[11] == 0x01 && (*encoded_chunk)[12] == 0x00 &&
          (*encoded_chunk)[15] == 0x04);

    const auto decoded_chunk = encoded_chunk
        ? deserialize_file_chunk(*encoded_chunk)
        : std::nullopt;
    CHECK(decoded_chunk.has_value());
    CHECK(decoded_chunk && decoded_chunk->transfer_id == chunk.transfer_id);
    CHECK(decoded_chunk && decoded_chunk->chunk_index == chunk.chunk_index);
    CHECK(decoded_chunk && decoded_chunk->data == chunk.data);

    FileTransferHeader two_chunk_header{
        99, 902, 900, 2, CryptoHash{}, "data.bin"};
    FileTransferChunk first_chunk{99, 0, {}};
    first_chunk.data.resize(two_chunk_header.chunk_size);
    FileTransferChunk final_chunk{99, 1, {0xaa, 0xbb}};
    CHECK(is_valid_file_chunk_for_header(two_chunk_header, first_chunk));
    CHECK(is_valid_file_chunk_for_header(two_chunk_header, final_chunk));
    final_chunk.data.push_back(0xcc);
    CHECK(!is_valid_file_chunk_for_header(two_chunk_header, final_chunk));
    final_chunk.data.pop_back();
    final_chunk.chunk_index = 2;
    CHECK(!is_valid_file_chunk_for_header(two_chunk_header, final_chunk));
    final_chunk.chunk_index = 1;
    final_chunk.transfer_id = 100;
    CHECK(!is_valid_file_chunk_for_header(two_chunk_header, final_chunk));

    const FileTransferHeader empty_header{
        7, 0, FILE_TRANSFER_MIN_CHUNK_SIZE, 1, CryptoHash{}, "empty.bin"};
    const FileTransferChunk empty_chunk{7, 0, {}};
    CHECK(is_valid_file_chunk_for_header(empty_header, empty_chunk));

    FileChunkTracker tracker;
    CHECK(!tracker.reset(0));
    CHECK(!tracker.reset(FILE_TRANSFER_MAX_CHUNKS + 1));
    CHECK(tracker.reset(3));
    CHECK(tracker.record(1) == FileChunkReceipt::Accepted);
    CHECK(tracker.record(1) == FileChunkReceipt::Duplicate);
    CHECK(tracker.received_count() == 1);
    CHECK(!tracker.complete());
    CHECK(tracker.record(3) == FileChunkReceipt::OutOfRange);
    CHECK(tracker.record(0) == FileChunkReceipt::Accepted);
    CHECK(tracker.record(2) == FileChunkReceipt::Accepted);
    CHECK(tracker.received_count() == 3);
    CHECK(tracker.complete());
    CHECK(tracker.reset(1));
    CHECK(tracker.received_count() == 0);
    CHECK(!tracker.received(0));

    NodeId alice{};
    NodeId bob{};
    alice[0] = 1;
    bob[0] = 2;
    std::map<FileTransferKey, FileChunkTracker> transfers;
    const FileTransferKey alice_42{alice, 42};
    const FileTransferKey bob_42{bob, 42};
    const FileTransferKey alice_43{alice, 43};
    CHECK(transfers[alice_42].reset(2));
    CHECK(transfers[bob_42].reset(2));
    CHECK(transfers[alice_43].reset(2));
    CHECK(transfers.size() == 3);
    CHECK(transfers[alice_42].record(0) == FileChunkReceipt::Accepted);
    CHECK(transfers[alice_42].record(0) == FileChunkReceipt::Duplicate);
    CHECK(transfers[bob_42].received_count() == 0);
    CHECK(transfers[alice_43].received_count() == 0);

    FileChunkTracker selective;
    CHECK(selective.reset(5));
    CHECK(selective.record(2) == FileChunkReceipt::Accepted);
    auto ranges = selective.acknowledged_ranges(2);
    CHECK(ranges.size() == 1 && ranges[0].first == 2 &&
          ranges[0].count == 1);
    CHECK(selective.record(0) == FileChunkReceipt::Accepted);
    CHECK(selective.record(1) == FileChunkReceipt::Accepted);
    ranges = selective.acknowledged_ranges(2);
    CHECK(ranges.size() == 1 && ranges[0].first == 0 &&
          ranges[0].count == 3);

    const FileTransferAck wire_ack{
        0x0102030405060708ULL, true, {{0, 3}, {5, 2}}};
    const auto encoded_ack = serialize_file_ack(wire_ack);
    CHECK(encoded_ack && encoded_ack->size() ==
          FILE_ACK_FIXED_SIZE + 2 * FILE_ACK_RANGE_SIZE);
    const auto decoded_ack = encoded_ack
        ? deserialize_file_ack(*encoded_ack)
        : std::nullopt;
    CHECK(decoded_ack && decoded_ack->transfer_id == wire_ack.transfer_id);
    CHECK(decoded_ack && decoded_ack->header_received);
    CHECK(decoded_ack && decoded_ack->ranges.size() == 2 &&
          decoded_ack->ranges[1].first == 5 &&
          decoded_ack->ranges[1].count == 2);
    FileTransferAck overlapping_ack{1, true, {{0, 3}, {2, 1}}};
    CHECK(!serialize_file_ack(overlapping_ack).has_value());
    if (encoded_ack) {
        auto bad_flags = *encoded_ack;
        bad_flags[8] = 0x80;
        CHECK(!deserialize_file_ack(bad_flags).has_value());
        auto truncated_ack = *encoded_ack;
        truncated_ack.pop_back();
        CHECK(!deserialize_file_ack(truncated_ack).has_value());
    }

    ManualClock send_clock;
    FileSendWindowConfig send_config;
    send_config.window_size = 3;
    send_config.retry_limit = 2;
    send_config.initial_rto = std::chrono::milliseconds(100);
    send_config.minimum_rto = std::chrono::milliseconds(50);
    send_config.maximum_rto = std::chrono::milliseconds(500);
    FileSendWindow send_window(send_config);
    CHECK(send_window.reset(5, send_clock.now()));
    auto action = send_window.poll(send_clock.now());
    CHECK(action.send_header && action.chunks.empty());
    CHECK(!send_window.poll(send_clock.now()).send_header);
    send_clock.advance(std::chrono::milliseconds(100));
    CHECK(send_window.poll(send_clock.now()).send_header);
    send_window.acknowledge(FileTransferAck{7, true, {}}, send_clock.now());
    action = send_window.poll(send_clock.now());
    CHECK(!action.send_header && action.chunks ==
          std::vector<uint32_t>({0, 1, 2}));
    send_window.acknowledge(
        FileTransferAck{7, true, {{1, 1}}}, send_clock.now());
    action = send_window.poll(send_clock.now());
    CHECK(action.chunks == std::vector<uint32_t>({3}));
    send_clock.advance(std::chrono::milliseconds(100));
    action = send_window.poll(send_clock.now());
    CHECK(action.chunks == std::vector<uint32_t>({0, 2, 3}));
    send_window.acknowledge(
        FileTransferAck{7, true, {{0, 3}}}, send_clock.now());
    action = send_window.poll(send_clock.now());
    CHECK(action.chunks == std::vector<uint32_t>({4}));
    send_window.acknowledge(
        FileTransferAck{7, true, {{3, 2}}}, send_clock.now());
    CHECK(send_window.complete());
    CHECK(send_window.acknowledged_count() == 5);

    ManualClock loss_clock;
    FileSendWindow loss_window(send_config);
    CHECK(loss_window.reset(1, loss_clock.now()));
    CHECK(loss_window.poll(loss_clock.now()).send_header);
    loss_window.acknowledge(
        FileTransferAck{9, true, {}}, loss_clock.now());
    CHECK(loss_window.rto() == std::chrono::milliseconds(50));
    CHECK(loss_window.poll(loss_clock.now()).chunks.size() == 1);
    loss_clock.advance(std::chrono::milliseconds(100));
    CHECK(loss_window.poll(loss_clock.now()).chunks.size() == 1);
    loss_clock.advance(std::chrono::milliseconds(100));
    CHECK(loss_window.poll(loss_clock.now()).chunks.size() == 1);
    loss_clock.advance(std::chrono::milliseconds(100));
    CHECK(loss_window.poll(loss_clock.now()).chunks.empty());
    CHECK(loss_window.failed());

    const std::filesystem::path temp_dir =
        std::filesystem::current_path() / "test_file_transfer_tmp";
    std::error_code fs_error;
    std::filesystem::remove_all(temp_dir, fs_error);
    fs_error.clear();
    CHECK(std::filesystem::create_directory(temp_dir, fs_error) && !fs_error);
    const std::string contents = "verified file contents";
    const auto write_test_file = [&](const std::filesystem::path& path) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(contents.data(),
                     static_cast<std::streamsize>(contents.size()));
        return static_cast<bool>(output);
    };
    const auto good_part = temp_dir / "good.part";
    const auto good_final = temp_dir / "good.bin";
    CHECK(write_test_file(good_part));
    const auto digest = hash_file_sha256(
        good_part.string(), static_cast<uint64_t>(contents.size()));
    CHECK(digest.has_value());
    CHECK(digest && verify_and_commit_file(
          good_part.string(), good_final.string(),
          static_cast<uint64_t>(contents.size()), *digest) ==
          FileCommitResult::Committed);
    CHECK(!std::filesystem::exists(good_part));
    CHECK(std::filesystem::exists(good_final));

    const auto bad_part = temp_dir / "bad.part";
    const auto bad_final = temp_dir / "bad.bin";
    CHECK(write_test_file(bad_part));
    CryptoHash wrong_digest = digest.value_or(CryptoHash{});
    wrong_digest[0] ^= 0xff;
    CHECK(verify_and_commit_file(
              bad_part.string(), bad_final.string(),
              static_cast<uint64_t>(contents.size()), wrong_digest) ==
          FileCommitResult::DigestMismatch);
    CHECK(std::filesystem::exists(bad_part));
    CHECK(!std::filesystem::exists(bad_final));
    CHECK(file_transfer_part_name(alice, 42) !=
          file_transfer_part_name(bob, 42));
    CHECK(file_transfer_part_name(alice, 42).ends_with(".part"));
    std::filesystem::remove_all(temp_dir, fs_error);
    CHECK(!fs_error);

    if (encoded_chunk) {
        auto truncated = *encoded_chunk;
        truncated.pop_back();
        CHECK(!deserialize_file_chunk(truncated).has_value());

        auto trailing = *encoded_chunk;
        trailing.push_back(0);
        CHECK(!deserialize_file_chunk(trailing).has_value());

        auto oversized_data = *encoded_chunk;
        oversized_data[12] = 0x7f;
        CHECK(!deserialize_file_chunk(oversized_data).has_value());
    }

    const std::vector<uint8_t> empty;
    CHECK(!deserialize_file_header(empty).has_value());
    CHECK(!deserialize_file_chunk(empty).has_value());

    std::printf("\n%d/%d tests passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
