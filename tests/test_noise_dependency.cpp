#include <noise/protocol.h>
#include <cstdio>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool ok = !!(cond); \
    passed += ok; \
    printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- pinned Noise-C dependency tests ---\n");

    CHECK(noise_init() == NOISE_ERROR_NONE);

    NoiseHandshakeState* initiator = nullptr;
    CHECK(noise_handshakestate_new_by_name(
        &initiator, "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        NOISE_ROLE_INITIATOR) == NOISE_ERROR_NONE);
    CHECK(initiator != nullptr);
    if (initiator) {
        CHECK(noise_handshakestate_get_role(initiator) ==
              NOISE_ROLE_INITIATOR);
        CHECK(noise_handshakestate_needs_local_keypair(initiator) != 0);
        CHECK(noise_handshakestate_needs_remote_public_key(initiator) != 0);
        CHECK(noise_handshakestate_free(initiator) == NOISE_ERROR_NONE);
    }

    NoiseHandshakeState* responder = nullptr;
    CHECK(noise_handshakestate_new_by_name(
        &responder, "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        NOISE_ROLE_RESPONDER) == NOISE_ERROR_NONE);
    CHECK(responder != nullptr);
    if (responder) {
        CHECK(noise_handshakestate_get_role(responder) ==
              NOISE_ROLE_RESPONDER);
        CHECK(noise_handshakestate_needs_local_keypair(responder) != 0);
        CHECK(noise_handshakestate_needs_remote_public_key(responder) == 0);
        CHECK(noise_handshakestate_free(responder) == NOISE_ERROR_NONE);
    }

    NoiseHandshakeState* unsupported = nullptr;
    CHECK(noise_handshakestate_new_by_name(
        &unsupported, "Noise_IK_448_ChaChaPoly_BLAKE2s",
        NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE);
    // Upstream frees a partially constructed state on this path without
    // clearing the caller's pointer. Never inspect or free it after failure.
    unsupported = nullptr;
    CHECK(noise_handshakestate_new_by_name(
        &unsupported, "Noise_IK_25519_AESGCM_BLAKE2s",
        NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE);

    printf("--- pinned Noise-C dependency: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
