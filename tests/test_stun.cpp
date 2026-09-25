#include "aegis/stun/stun.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- STUN RFC 5389 tests ---\n");

    platform_init_winsock();

    uint8_t tx_id[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    auto req = create_stun_binding_request(tx_id);

    CHECK(req.size() == 20);
    CHECK(req[0] == 0x00 && req[1] == 0x01); // Binding request
    CHECK(req[4] == 0x21 && req[5] == 0x12 && req[6] == 0xA4 && req[7] == 0x42); // Magic cookie

    // Synthesize a valid STUN Binding Response
    // Header (20 bytes): type=0x0101, len=12 (0x000c), cookie=0x2112A442, tx_id
    // Attribute XOR-MAPPED-ADDRESS: type=0x0020, len=8, reserved=0, family=1, xor_port, xor_ip
    std::vector<uint8_t> resp = {
        0x01, 0x01, 0x00, 0x0C,
        0x21, 0x12, 0xA4, 0x42,
        1,2,3,4,5,6,7,8,9,10,11,12,
        // Attr header
        0x00, 0x20, 0x00, 0x08,
        0x00, 0x01
    };

    // XOR 192.168.1.50 (0xC0A80132) with 0x2112A442 = 0xE1BAA570
    // XOR port 51820 (0xCA6C) with 0x2112 = 0xEB7E
    uint16_t xor_port = 0xEB7E;
    uint32_t xor_ip = 0xE1BAA570;

    resp.push_back((uint8_t)(xor_port >> 8));
    resp.push_back((uint8_t)(xor_port & 0xFF));

    resp.push_back((uint8_t)(xor_ip >> 24));
    resp.push_back((uint8_t)(xor_ip >> 16));
    resp.push_back((uint8_t)(xor_ip >> 8));
    resp.push_back((uint8_t)(xor_ip & 0xFF));

    auto parsed = parse_stun_binding_response(resp.data(), resp.size(), tx_id);
    CHECK(parsed.has_value());
    if (parsed) {
        CHECK(ntohs(parsed->port) == 51820);
        uint32_t ip_host = ntohl(parsed->ip);
        CHECK(ip_host == 0xC0A80132); // 192.168.1.50
    }

    // Exact declared length and complete attribute validation are required.
    {
        auto trailing = resp;
        trailing.push_back(0);
        CHECK(!parse_stun_binding_response(
            trailing.data(), trailing.size(), tx_id).has_value());

        auto truncated = resp;
        truncated.pop_back();
        CHECK(!parse_stun_binding_response(
            truncated.data(), truncated.size(), tx_id).has_value());

        auto bad_declared_length = resp;
        bad_declared_length[3] = 0x08;
        CHECK(!parse_stun_binding_response(
            bad_declared_length.data(), bad_declared_length.size(), tx_id).has_value());

        auto malformed_after_valid = resp;
        malformed_after_valid[3] = 0x10;
        malformed_after_valid.insert(
            malformed_after_valid.end(), {0x00, 0x01, 0x00, 0x08});
        CHECK(!parse_stun_binding_response(
            malformed_after_valid.data(), malformed_after_valid.size(), tx_id).has_value());

        uint8_t wrong_tx_id[12] = {};
        CHECK(!parse_stun_binding_response(
            resp.data(), resp.size(), wrong_tx_id).has_value());
    }

    platform_cleanup_winsock();

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
