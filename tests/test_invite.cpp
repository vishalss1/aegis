#include "aegis/invite/invite.hpp"
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
    printf("--- invite code tests ---\n");

    InvitePayload p1;
    for (size_t i = 0; i < 32; i++) {
        p1.network_id[i] = (uint8_t)(i + 1);
        p1.bootstrap_pubkey[i] = (uint8_t)(0x80 | i);
        p1.creator_node_id[i] = (uint8_t)(0x40 | i);
    }
    p1.bootstrap_endpoint = Endpoint::from_parts(203, 0, 113, 2, 51820);
    p1.bootstrap_prefix = (10 << 24) | (10 << 16) | (0 << 8) | 2; // 10.10.0.2
    p1.bootstrap_prefix_len = 32;
    p1.network_name = "test mesh";

    std::string encoded = encode_invite(p1);
    printf("Encoded invite: %s\n", encoded.c_str());

    CHECK(encoded.rfind("AEGIS1:", 0) == 0);

    auto decoded = decode_invite(encoded);
    CHECK(decoded.has_value());

    if (decoded) {
        CHECK(decoded->network_id == p1.network_id);
        CHECK(decoded->bootstrap_pubkey == p1.bootstrap_pubkey);
        CHECK(decoded->creator_node_id == p1.creator_node_id);
        CHECK(decoded->bootstrap_endpoint.ip == p1.bootstrap_endpoint.ip);
        CHECK(decoded->bootstrap_endpoint.port == p1.bootstrap_endpoint.port);
        CHECK(decoded->bootstrap_prefix == p1.bootstrap_prefix);
        CHECK(decoded->bootstrap_prefix_len == p1.bootstrap_prefix_len);
        CHECK(decoded->network_name == p1.network_name);
    }

    // Invalid tests
    CHECK(!decode_invite("INVALID:12345").has_value());
    CHECK(!decode_invite("AEGIS1:invalid_b64!!!").has_value());
    CHECK(!decode_invite("AEGIS1:tooShort").has_value());
    CHECK(!decode_invite(encoded + "A").has_value());
    CHECK(!decode_invite(encoded.substr(0, encoded.size() - 1)).has_value());

    InvitePayload bad_prefix = p1;
    bad_prefix.bootstrap_prefix_len = 33;
    CHECK(!decode_invite(encode_invite(bad_prefix)).has_value());

    InvitePayload long_name = p1;
    long_name.network_name.assign(80, 'x');
    const auto decoded_long_name = decode_invite(encode_invite(long_name));
    CHECK(decoded_long_name.has_value());
    CHECK(decoded_long_name && decoded_long_name->network_name.size() == 64);

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
