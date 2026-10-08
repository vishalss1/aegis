#include "aegis/identity/revocation.hpp"
#include <cstdio>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    ++tests; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    NetworkId network{};
    network[0] = 1;
    const Identity issuer = Identity::create(network);
    Key nonce{};
    nonce[0] = 0xA7;
    auto revocation = sign_membership_revocation(
        network, issuer.signing_keypair.public_key,
        issuer.signing_keypair.private_key, nonce, 4, 1'850'000'000);
    CHECK(revocation.has_value());
    CHECK(revocation && verify_membership_revocation(*revocation));

    MembershipRevocationStore store;
    CHECK(revocation && store.add(*revocation));
    CHECK(store.size() == 1);
    CHECK(revocation && !store.add(*revocation));
    auto newer = sign_membership_revocation(
        network, issuer.signing_keypair.public_key,
        issuer.signing_keypair.private_key, nonce, 5, 1'850'000'001);
    CHECK(newer && store.add(*newer));
    CHECK(store.size() == 1);
    CHECK(store.snapshot()[0].revocation_epoch == 5);

    const auto encoded = revocation
        ? serialize_membership_revocations({*revocation}) : std::nullopt;
    CHECK(encoded.has_value());
    const auto decoded = encoded
        ? deserialize_membership_revocations(encoded->data(), encoded->size())
        : std::nullopt;
    CHECK(decoded && decoded->size() == 1);
    CHECK(decoded && (*decoded)[0].enrollment_nonce == nonce);
    if (encoded) {
        auto tampered = *encoded;
        tampered[5] ^= 1;
        CHECK(!deserialize_membership_revocations(
            tampered.data(), tampered.size()).has_value());
        tampered = *encoded;
        tampered.push_back(0);
        CHECK(!deserialize_membership_revocations(
            tampered.data(), tampered.size()).has_value());
    }
    CHECK(!serialize_membership_revocations({}).has_value());
    std::vector<MembershipRevocation> excessive(
        MEMBERSHIP_REVOCATION_MAX_RECORDS + 1,
        revocation.value_or(MembershipRevocation{}));
    CHECK(!serialize_membership_revocations(excessive).has_value());
    CHECK(!sign_membership_revocation(
        network, issuer.signing_keypair.public_key, Key{}, nonce, 1, 1)
        .has_value());

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
