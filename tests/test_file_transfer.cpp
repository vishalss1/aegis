#include "aegis/file/transfer.hpp"
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("--- file transfer framing tests ---\n");

    const FileTransferHeader header{
        0x0102030405060708ULL,
        0x1112131415161718ULL,
        0x21222324U,
        "report.bin"
    };
    const auto encoded_header = serialize_file_header(header);
    CHECK(encoded_header.has_value());
    CHECK(encoded_header && encoded_header->size() ==
          FILE_HEADER_FIXED_SIZE + header.filename.size());
    CHECK(encoded_header && (*encoded_header)[0] == 0x01 &&
          (*encoded_header)[7] == 0x08 && (*encoded_header)[8] == 0x11 &&
          (*encoded_header)[15] == 0x18 && (*encoded_header)[16] == 0x21 &&
          (*encoded_header)[19] == 0x24 && (*encoded_header)[20] == 0x00 &&
          (*encoded_header)[21] == header.filename.size());

    const auto decoded_header = encoded_header
        ? deserialize_file_header(*encoded_header)
        : std::nullopt;
    CHECK(decoded_header.has_value());
    CHECK(decoded_header && decoded_header->transfer_id == header.transfer_id);
    CHECK(decoded_header && decoded_header->file_size == header.file_size);
    CHECK(decoded_header && decoded_header->total_chunks == header.total_chunks);
    CHECK(decoded_header && decoded_header->filename == header.filename);

    if (encoded_header) {
        auto truncated = *encoded_header;
        truncated.pop_back();
        CHECK(!deserialize_file_header(truncated).has_value());

        auto trailing = *encoded_header;
        trailing.push_back(0);
        CHECK(!deserialize_file_header(trailing).has_value());

        auto oversized_name = *encoded_header;
        oversized_name[20] = 0x7f;
        oversized_name[21] = 0xff;
        CHECK(!deserialize_file_header(oversized_name).has_value());
    }

    FileTransferHeader long_name;
    long_name.filename.assign(
        static_cast<size_t>(std::numeric_limits<uint16_t>::max()) + 1, 'a');
    CHECK(!serialize_file_header(long_name).has_value());

    const FileTransferChunk chunk{
        0x3132333435363738ULL,
        0x41424344U,
        {0xde, 0xad, 0xbe, 0xef}
    };
    const auto encoded_chunk = serialize_file_chunk(chunk);
    CHECK(encoded_chunk.has_value());
    CHECK(encoded_chunk && encoded_chunk->size() ==
          FILE_CHUNK_FIXED_SIZE + chunk.data.size());
    CHECK(encoded_chunk && (*encoded_chunk)[0] == 0x31 &&
          (*encoded_chunk)[7] == 0x38 && (*encoded_chunk)[8] == 0x41 &&
          (*encoded_chunk)[11] == 0x44 && (*encoded_chunk)[12] == 0x00 &&
          (*encoded_chunk)[15] == 0x04);

    const auto decoded_chunk = encoded_chunk
        ? deserialize_file_chunk(*encoded_chunk)
        : std::nullopt;
    CHECK(decoded_chunk.has_value());
    CHECK(decoded_chunk && decoded_chunk->transfer_id == chunk.transfer_id);
    CHECK(decoded_chunk && decoded_chunk->chunk_index == chunk.chunk_index);
    CHECK(decoded_chunk && decoded_chunk->data == chunk.data);

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
