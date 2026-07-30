#include "aegis/packet/packet.hpp"
#include <cstdio>
#include <cstring>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

// Valid IPv4/ICMP packet: 10.10.0.2 -> 10.10.0.1, id=0xabcd, ttl=64,
// checksum=0xbadd, ICMP echo (type=8, code=0), payload=32 zero bytes
static const uint8_t VALID_IP[] = {
    0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd, 0x00, 0x00,
    0x40, 0x01, 0xba, 0xdd, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Bad checksum: same as VALID_IP but with checksum field zeroed
static const uint8_t BAD_CSUM_IP[] = {
    0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd, 0x00, 0x00,
    0x40, 0x01, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// IPv6 packet: version nibble = 6
static const uint8_t IPV6_PACKET[] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01,
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9e, 0x59, 0x84, 0xbe, 0x84, 0xa6, 0xbc, 0x8d,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
};

int main() {
    printf("--- packet parse tests ---\n");

    // 1. Valid IPv4 packet should parse
    {
        auto r = IPPacket::parse(VALID_IP, sizeof(VALID_IP));
        CHECK(r.has_value());
        if (r) {
            CHECK(r->version_ihl == 0x45);
            CHECK(r->total_length == 60);
            CHECK(r->protocol == 1);
            CHECK(r->ttl == 64);
            CHECK(r->source_ip == 0x0a0a0002);
            CHECK(r->dest_ip   == 0x0a0a0001);
            CHECK(r->payload_length == 40);
            CHECK(r->payload != nullptr);
        }
    }

    // 2. Truncated (< 20 bytes) should reject
    {
        auto r = IPPacket::parse(VALID_IP, 19);
        CHECK(!r.has_value());
    }

    // 3. Truncated (less than header_len) should reject
    {
        auto r = IPPacket::parse(VALID_IP, 15);
        CHECK(!r.has_value());
    }

    // 4. IPv6 should reject as non-IPv4
    {
        auto r = IPPacket::parse(IPV6_PACKET, sizeof(IPV6_PACKET));
        CHECK(!r.has_value());
    }

    // 5. Bad checksum should reject
    {
        auto r = IPPacket::parse(BAD_CSUM_IP, sizeof(BAD_CSUM_IP));
        CHECK(!r.has_value());
    }

    // 6. Total length shorter than header should reject
    {
        // Craft a packet where IHL=5 (20 bytes) but total_length=16
        uint8_t bad_total[20] = {};
        bad_total[0] = 0x45;               // ver=4, ihl=5
        bad_total[2] = 0x00;               // total_len high
        bad_total[3] = 0x10;               // total_len low = 16 (< 20)
        // Need to compute checksum over 20 bytes with csum field=0
        bad_total[10] = 0;                 // csum high
        bad_total[11] = 0;                 // csum low
        auto r = IPPacket::parse(bad_total, sizeof(bad_total));
        CHECK(!r.has_value());
    }

    // 7. IHL < 5 should reject
    {
        uint8_t bad_ihl[20] = {};
        bad_ihl[0] = 0x44;                 // ver=4, ihl=4 (invalid)
        // Fill rest minimally so length checks pass
        bad_ihl[2] = 0x00;
        bad_ihl[3] = 20;                   // total_length = 20
        bad_ihl[10] = 0;
        bad_ihl[11] = 0;
        auto r = IPPacket::parse(bad_ihl, sizeof(bad_ihl));
        CHECK(!r.has_value());
    }

    // 8. ip_checksum helper on valid packet header returns 0xFFFF
    {
        uint16_t csum = ip_checksum(VALID_IP, 20);
        CHECK(csum == 0xFFFF);
    }

    // 9. ip_checksum on bad-csum packet header does NOT return 0xFFFF
    {
        uint16_t csum = ip_checksum(BAD_CSUM_IP, 20);
        CHECK(csum != 0xFFFF);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
