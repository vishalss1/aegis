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
        CHECK(decoded->bootstrap_endpoint.address == p1.bootstrap_endpoint.address);
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

    NetworkId grant_network{};
    grant_network[0] = 9;
    const Identity issuer = Identity::create(grant_network);
    Aegis2MembershipGrant grant;
    grant.network_id = grant_network;
    grant.issuer_signing_public_key = issuer.signing_keypair.public_key;
    grant.issuer_node_id = issuer.node_id;
    grant.enrollment_nonce[0] = 0xA5;
    grant.issued_at = 1'800'000'000;
    grant.expires_at = 1'900'000'000;
    grant.capabilities = 0x5;
    grant.revocation_epoch = 3;
    grant.allowed_prefixes.push_back({0x0A000000, 24});
    Aegis2BootstrapCandidate candidate;
    candidate.x25519_public_key = issuer.keypair.public_key;
    candidate.endpoint = Endpoint::from_parts(203, 0, 113, 9, 51820);
    grant.bootstrap_candidates.push_back(candidate);
    const std::string aegis2 = encode_aegis2_grant(
        grant, issuer.signing_keypair.private_key);
    CHECK(aegis2.rfind("AEGIS2:", 0) == 0);
    const auto decoded_grant = decode_aegis2_grant(aegis2);
    CHECK(decoded_grant.has_value());
    CHECK(!decode_invite(aegis2).has_value());
    CHECK(decoded_grant && decoded_grant->network_id == grant.network_id);
    CHECK(decoded_grant && decoded_grant->issuer_node_id == grant.issuer_node_id);
    CHECK(decoded_grant && decoded_grant->allowed_prefixes.size() == 1);
    CHECK(decoded_grant && decoded_grant->bootstrap_candidates.size() == 1);
    CHECK(decoded_grant && decoded_grant->capabilities == grant.capabilities);
    CHECK(decoded_grant && validate_aegis2_grant(
        *decoded_grant, 1'850'000'000, AEGIS2_CAPABILITY_JOIN));
    CHECK(decoded_grant && !validate_aegis2_grant(
        *decoded_grant, 1'900'000'000, AEGIS2_CAPABILITY_JOIN));
    CHECK(decoded_grant && !validate_aegis2_grant(
        *decoded_grant, 1'799'999'999, AEGIS2_CAPABILITY_JOIN));
    CHECK(decoded_grant && !validate_aegis2_grant(
        *decoded_grant, 1'850'000'000, AEGIS2_CAPABILITY_ADMIN));
    CHECK(decoded_grant && !validate_aegis2_grant(
        *decoded_grant, 1'850'000'000, 1ull << 63));
    CHECK(!decode_aegis2_grant(aegis2 + "A").has_value());
    Key unrelated_signing_key{};
    CHECK(encode_aegis2_grant(grant, unrelated_signing_key).empty());
    if (aegis2.size() > 16) {
        std::string tampered = aegis2;
        tampered[16] = tampered[16] == 'A' ? 'B' : 'A';
        CHECK(!decode_aegis2_grant(tampered).has_value());
    }
    Aegis2MembershipGrant oversized = grant;
    oversized.allowed_prefixes.resize(AEGIS2_MAX_PREFIXES + 1);
    CHECK(encode_aegis2_grant(
        oversized, issuer.signing_keypair.private_key).empty());

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
