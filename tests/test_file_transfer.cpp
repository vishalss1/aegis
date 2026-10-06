#include "aegis/file/transfer.hpp"
#include <algorithm>
#include <cstdio>
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
        32770,
        2,
        "report.bin"
    };
    const auto encoded_header = serialize_file_header(header);
    CHECK(encoded_header.has_value());
    CHECK(encoded_header && encoded_header->size() ==
          FILE_HEADER_FIXED_SIZE + header.filename.size());
    CHECK(encoded_header && (*encoded_header)[0] == 0x01 &&
          (*encoded_header)[7] == 0x08 && (*encoded_header)[14] == 0x80 &&
          (*encoded_header)[15] == 0x02 && (*encoded_header)[18] == 0x00 &&
          (*encoded_header)[19] == 0x02 && (*encoded_header)[20] == 0x00 &&
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

        auto traversal_name = *encoded_header;
        const std::string traversal = "../bad.bin";
        std::copy(traversal.begin(), traversal.end(),
                  traversal_name.begin() + FILE_HEADER_FIXED_SIZE);
        CHECK(!deserialize_file_header(traversal_name).has_value());
    }

    FileTransferHeader long_name;
    long_name.transfer_id = 1;
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
    CHECK(file_transfer_chunk_count(0) == 1);
    CHECK(file_transfer_chunk_count(FILE_TRANSFER_MAX_FILE_SIZE) ==
          FILE_TRANSFER_MAX_CHUNKS);
    CHECK(file_transfer_chunk_count(FILE_TRANSFER_MAX_FILE_SIZE + 1) == 0);

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

    FileTransferHeader two_chunk_header{99, 32770, 2, "data.bin"};
    FileTransferChunk first_chunk{99, 0, {}};
    first_chunk.data.resize(FILE_TRANSFER_CHUNK_SIZE);
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

    const FileTransferHeader empty_header{7, 0, 1, "empty.bin"};
    const FileTransferChunk empty_chunk{7, 0, {}};
    CHECK(is_valid_file_chunk_for_header(empty_header, empty_chunk));

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
