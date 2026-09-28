/*
 * Aegis compiles only the Noise-C algorithms required by
 * Noise_IK_25519_ChaChaPoly_BLAKE2s.  The generic Noise-C factories retain
 * references to other algorithms, so these constructors explicitly report
 * them as unavailable by returning NULL.
 */
#include "internal.h"

NoiseCipherState *noise_aesgcm_new(void) { return 0; }
NoiseHashState *noise_blake2b_new(void) { return 0; }
NoiseHashState *noise_sha256_new(void) { return 0; }
NoiseHashState *noise_sha512_new(void) { return 0; }
NoiseDHState *noise_curve448_new(void) { return 0; }
NoiseDHState *noise_newhope_new(void) { return 0; }
