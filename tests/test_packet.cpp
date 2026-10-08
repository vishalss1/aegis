#include "aegis/packet/packet.hpp"
#include "aegis/packet/mtu.hpp"
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

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

    // 10. Physical-wire overhead follows route encapsulation depth
    {
        CHECK(PACKET_VERSION == 2);
        CHECK(session_padded_plaintext_size(0) == 64);
        CHECK(session_padded_plaintext_size(60) == 64);
        CHECK(session_padded_plaintext_size(61) == 128);
        CHECK(session_padded_plaintext_size(20, 32) == 32);
        CHECK(session_padded_plaintext_size(125, 128) == 256);
        CHECK(!is_supported_session_padding_bucket(96));
        CHECK(session_frame_overhead(32) == 79);
        CHECK(session_frame_overhead(64) == 111);
        CHECK(session_frame_overhead(128) == 175);
        CHECK(session_frame_overhead(256) == 303);
        CHECK(!wire_overhead_for_route_depth(2, 96).has_value());
        CHECK(session_padded_plaintext_size(
                  SESSION_MAX_LOGICAL_PAYLOAD_SIZE) ==
              SESSION_MAX_PAYLOAD_SIZE);
        CHECK(OUTER_IPV4_UDP_OVERHEAD == 28);
        CHECK(SESSION_FRAME_OVERHEAD == 111);
        CHECK(RELAY_SOURCE_OVERHEAD == 33);
        CHECK(ONION_OVERHEAD == 60);

        const auto direct = wire_overhead_for_route_depth(1);
        CHECK(direct.has_value());
        CHECK(direct && *direct == 139);

        const auto two_hop = wire_overhead_for_route_depth(2);
        const auto three_hop = wire_overhead_for_route_depth(3);
        CHECK(two_hop && *two_hop == 292);
        CHECK(three_hop && *three_hop == 352);
        CHECK(two_hop && three_hop && *three_hop - *two_hop == 60);

        const auto maximum =
            wire_overhead_for_route_depth(ONION_MAX_HOPS);
        CHECK(maximum && *maximum == 652);
        CHECK(!wire_overhead_for_route_depth(0).has_value());
        CHECK(!wire_overhead_for_route_depth(
            ONION_MAX_HOPS + 1).has_value());

        constexpr std::array<size_t, ONION_MAX_HOPS> expected_mtu = {
            1361, 1208, 1148, 1088, 1028, 968, 908, 848
        };
        for (size_t depth = 1; depth <= ONION_MAX_HOPS; ++depth) {
            const auto overhead = wire_overhead_for_route_depth(depth);
            const auto mtu = safe_overlay_mtu(DEFAULT_UNDERLAY_MTU, depth);
            CHECK(overhead.has_value());
            CHECK(mtu.has_value());
            CHECK(mtu && *mtu == expected_mtu[depth - 1]);
            CHECK(mtu && overhead &&
                  *mtu + *overhead == DEFAULT_UNDERLAY_MTU);
            CHECK(mtu && overhead &&
                  *mtu + 1 + *overhead > DEFAULT_UNDERLAY_MTU);
        }

        CHECK(safe_overlay_mtu(1228, ONION_MAX_HOPS) ==
              MINIMUM_IPV4_MTU);
        CHECK(!safe_overlay_mtu(1227, ONION_MAX_HOPS).has_value());
        CHECK(!safe_overlay_mtu(MAXIMUM_IPV4_MTU + 1, 1).has_value());
    }

    // 11. Decrypted inner packets must be exact and fit the adapter MTU
    {
        CHECK(validate_inner_ipv4_packet(
                  VALID_IP, sizeof(VALID_IP), sizeof(VALID_IP)) ==
              InnerPacketStatus::Valid);
        CHECK(validate_inner_ipv4_packet(
                  VALID_IP, sizeof(VALID_IP), sizeof(VALID_IP) - 1) ==
              InnerPacketStatus::Oversize);
        CHECK(validate_inner_ipv4_packet(
                  BAD_CSUM_IP, sizeof(BAD_CSUM_IP), sizeof(BAD_CSUM_IP)) ==
              InnerPacketStatus::Invalid);
        CHECK(validate_inner_ipv4_packet(
                  VALID_IP, sizeof(VALID_IP) - 1, sizeof(VALID_IP)) ==
              InnerPacketStatus::Invalid);
        CHECK(validate_inner_ipv4_packet(
                  IPV6_PACKET, sizeof(IPV6_PACKET), sizeof(IPV6_PACKET)) ==
              InnerPacketStatus::Invalid);
        CHECK(validate_inner_ipv4_packet(
                  nullptr, sizeof(VALID_IP), sizeof(VALID_IP)) ==
              InnerPacketStatus::Invalid);

        std::vector<uint8_t> trailing(
            VALID_IP, VALID_IP + sizeof(VALID_IP));
        trailing.push_back(0);
        CHECK(validate_inner_ipv4_packet(
                  trailing.data(), trailing.size(), trailing.size()) ==
              InnerPacketStatus::Invalid);
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
