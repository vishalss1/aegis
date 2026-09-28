#include "internal.h"
#include "crypto/chacha/chacha.h"
#include <noise/protocol/aegis.h>
#include <string.h>

// Prefix of the pinned reference backend's NoiseChaChaPolyState. Aegis is
// Windows-only and the retained backend stores the 256-bit key as eight
// little-endian words immediately after ChaCha's four constant words.
typedef struct
{
    struct NoiseCipherState_s parent;
    chacha_ctx chacha;
} AegisNoiseChaChaPolyPrefix;

int aegis_noise_cipherstate_export_key(
    const NoiseCipherState *state, uint8_t *key, size_t key_len)
{
    const AegisNoiseChaChaPolyPrefix *chachapoly;
    if (!state || !key)
        return NOISE_ERROR_INVALID_PARAM;
    if (state->cipher_id != NOISE_CIPHER_CHACHAPOLY ||
            !state->has_key || state->key_len != 32 || key_len != 32)
        return NOISE_ERROR_INVALID_STATE;

    chachapoly = (const AegisNoiseChaChaPolyPrefix *)state;
    memcpy(key, ((const uint8_t *)(chachapoly->chacha.input)) + 16, 32);
    return NOISE_ERROR_NONE;
}
