#include "aegis/protocol/wire.hpp"
#include "aegis/packet/header.hpp"
#include <array>
#include <cstdio>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    std::printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    std::printf("--- wire codec tests ---\n");

    // ---- 1. Integers and byte strings use canonical network byte order ------
    {
        std::array<uint8_t, 19> storage{};
        WireWriter writer(storage);
        const std::array<uint8_t, 4> tail = {0x10, 0x20, 0x30, 0x40};

        CHECK(writer.write_u8(0xAB));
        CHECK(writer.write_u16(0x1234));
        CHECK(writer.write_u32(0x56789ABC));
        CHECK(writer.write_u64(0x0123456789ABCDEF));
        CHECK(writer.write_bytes(tail));
        CHECK(writer.finished());
        CHECK(writer.position() == storage.size());
        CHECK(writer.remaining() == 0);
        CHECK(writer.written().size() == storage.size());

        const std::array<uint8_t, 19> expected = {
            0xAB, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x20, 0x30, 0x40
        };
        CHECK(storage == expected);
    }

    // ---- 2. Reader mirrors the writer and exposes trailing bytes ------------
    {
        const std::array<uint8_t, 18> encoded = {
            0xAB, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x20, 0xFF
        };
        WireReader reader(encoded);

        CHECK(reader.read_u8() == static_cast<uint8_t>(0xAB));
        CHECK(reader.read_u16() == static_cast<uint16_t>(0x1234));
        CHECK(reader.read_u32() == UINT32_C(0x56789ABC));
        CHECK(reader.read_u64() == UINT64_C(0x0123456789ABCDEF));
        const auto bytes = reader.read_bytes(2);
        CHECK(bytes.has_value());
        CHECK(bytes && (*bytes)[0] == 0x10 && (*bytes)[1] == 0x20);
        CHECK(!reader.finished());
        CHECK(reader.remaining() == 1);
        CHECK(reader.read_u8() == static_cast<uint8_t>(0xFF));
        CHECK(reader.finished());
    }

    // ---- 3. Failed writes are atomic ----------------------------------------
    {
        std::array<uint8_t, 3> storage = {0xEE, 0xEE, 0xEE};
        WireWriter writer(storage);

        CHECK(writer.write_u16(0x1234));
        CHECK(!writer.write_u16(0x5678));
        CHECK(writer.position() == 2);
        CHECK(writer.remaining() == 1);
        CHECK(storage[0] == 0x12 && storage[1] == 0x34);
        CHECK(storage[2] == 0xEE);
    }

    // ---- 4. Failed reads are atomic -----------------------------------------
    {
        const std::array<uint8_t, 3> encoded = {0x12, 0x34, 0x56};
        WireReader reader(encoded);

        CHECK(reader.read_u16() == static_cast<uint16_t>(0x1234));
        CHECK(!reader.read_u32().has_value());
        CHECK(reader.position() == 2);
        CHECK(reader.remaining() == 1);
        CHECK(reader.read_u8() == static_cast<uint8_t>(0x56));
        CHECK(reader.finished());
        CHECK(!reader.read_u8().has_value());
        CHECK(reader.position() == encoded.size());
    }

    // ---- 5. Empty byte ranges are valid and do not move the cursor ----------
    {
        std::array<uint8_t, 0> storage{};
        WireWriter writer(storage);
        WireReader reader(storage);

        CHECK(writer.write_bytes({}));
        CHECK(writer.finished());
        CHECK(reader.read_bytes(0).has_value());
        CHECK(reader.finished());
    }

    // ---- 6. Packet headers use the bounded canonical codec ------------------
    {
        const PacketHeader header{
            PACKET_VERSION, TYPE_RELAY, FLAG_RELAY, 0,
            UINT32_C(0x12345678), UINT32_C(0x90ABCDEF), 512};
        const auto encoded = serialize_packet_header(header);
        const auto decoded = parse_packet_header(encoded);
        CHECK(decoded.has_value());
        CHECK(decoded && decoded->version == header.version);
        CHECK(decoded && decoded->packet_type == header.packet_type);
        CHECK(decoded && decoded->flags == header.flags);
        CHECK(decoded && decoded->reserved == 0);
        CHECK(decoded && decoded->session_id == header.session_id);
        CHECK(decoded && decoded->sequence_number == header.sequence_number);
        CHECK(decoded && decoded->payload_length == header.payload_length);
        CHECK(!parse_packet_header(
            std::span<const uint8_t>(encoded).first(encoded.size() - 1)).has_value());
        std::array<uint8_t, PACKET_HEADER_SIZE + 1> trailing{};
        std::copy(encoded.begin(), encoded.end(), trailing.begin());
        CHECK(!parse_packet_header(trailing).has_value());
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
