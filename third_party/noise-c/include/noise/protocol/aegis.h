#ifndef AEGIS_NOISE_PROTOCOL_H
#define AEGIS_NOISE_PROTOCOL_H

#include <noise/protocol/cipherstate.h>

#ifdef __cplusplus
extern "C" {
#endif

// Aegis-only compatibility hook for the pinned reference ChaChaPoly backend.
// Copies the raw 32-byte split key so the dependency state can be destroyed.
int aegis_noise_cipherstate_export_key(
    const NoiseCipherState *state, uint8_t *key, size_t key_len);

#ifdef __cplusplus
};
#endif

#endif
