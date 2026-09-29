# Noise Revision 30-to-34 Compatibility Review

## Scope and conclusion

This review compares the pinned Noise-C implementation at commit
`cfe25410979a87391bb9ac8d4d4bef64e9f268c6`, whose documentation targets
Noise revision 30, with the official Noise specification tags below:

| Revision | Specification commit |
| --- | --- |
| 30 | `5f83bfe69396cfb7e70c4b8565b23ede24fe0ca5` |
| 31 | `ddffc62f68b18147a74351c7fdafb58de3ce9dab` |
| 32 | `87c02af1bd292100631ef9929565d4c11359f109` |
| 33 | `41d478d3dd97d77a6695f4d6cf6283e2830e9ca6` |
| 34 | `ecdf084ece2bf92b16b1201b6ae5c99d23fb4151` |

The reviewed Aegis suite, `Noise_IK_25519_ChaChaPoly_BLAKE2s`, is compatible
with revision 34. No dependency patch is required for this fundamental,
non-PSK IK handshake. The conclusion is deliberately limited to the suite and
wrapper surface that Aegis exposes; it does not approve every pattern or API in
the retained generic Noise-C source.

The official IK pattern is unchanged across the reviewed revisions:

```text
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

## Revision-by-revision assessment

| Change | Effect on Aegis IK |
| --- | --- |
| Revision 31 replaced the older `dhxy` spelling with canonical DH-token names and removed SSK material. | Not a wire or key-schedule change. The pinned token sequence is `e, es, s, ss` then `e, ee, se`. |
| Revision 32 specified DH-error handshake failure, failure-safe decrypt nonces, transport error handling, `GetHandshakeHash()`, rekeying, and PSK `MixKeyAndHash()` behavior. | Noise-C propagates DH and AEAD errors, increments a decrypt nonce only after successful authentication, exposes the final handshake hash, and derives the two split keys with HKDF. PSK paths are outside the wrapper. Aegis additionally destroys the complete dependency state after any operation error. |
| Revision 33 clarified protocol-name grammar, fallback modifiers, one-ephemeral-per-handshake, half-duplex, and out-of-order transport use. | The wrapper constructs the exact standard protocol name and injects one freshly generated ephemeral per side. It exposes neither fallback nor Noise transport-state nonce APIs. |
| Revision 34 marked fundamental patterns stable, clarified pre-message hash order and invalid DH identity values, prohibited repeated DH operations, added deferred patterns, replaced fallback notation with Bob-initiated patterns, and expanded security guidance. | IK has one responder pre-message key, no repeated DH operation, and no deferred token. Aegis's independent known-answer gate confirms the resulting transcript, handshake hash, split keys, and first transport ciphertext. |

## Pinned-source evidence

- `src/protocol/patterns.c` encodes the fundamental IK tokens in the required
  order and requires the initiator's remote static key.
- `src/protocol/handshakestate.c` hashes the prologue before pre-message keys,
  executes each pattern token, propagates DH errors, swaps split states for the
  responder role, and exposes the completed handshake hash.
- `src/protocol/symmetricstate.c` leaves the handshake hash unchanged when
  AEAD authentication fails and uses the two-output HKDF construction for
  `Split()`.
- `src/protocol/cipherstate.c` increments the nonce only after a successful
  decrypt.
- `src/backend/ref/cipher-chachapoly.c` constructs the Noise ChaChaPoly nonce
  with a 32-bit zero prefix and the 64-bit little-endian counter.
- `src/backend/ref/dh-curve25519.c` implements X25519 but retains Noise-C's
  revision-30 null-public-key convention. Revision 34 permits rejecting the DH
  identity element; it does not change valid-key results. Aegis's negative
  gate proves that an all-zero transmitted ephemeral cannot complete the IK
  handshake, and the wrapper destroys state on the authentication failure.

`test_noise_dependency` now asserts the parsed prefix, pattern, DH, cipher,
hash, and absence of a hybrid algorithm. `test_noise_ik` provides the
independent Cacophony known-answer gate and failure cases. Together these
tests make the source-review conclusions executable for the exposed surface.

## Excluded revision-34 features

Aegis does not expose PSK modifiers, deferred patterns, Bob-initiated or
fallback patterns, half-duplex negotiation, out-of-order Noise transport
nonces, or handshake application payloads. Changes to those facilities cannot
be used to infer compatibility without a separate review.

Revision 34 also warns that a Noise static key should remain within Noise and
one hash-algorithm domain. Aegis uses its identity X25519 key only with
BLAKE2s-based Noise IK. Static-key compromise retains the IK security
consequences described by the specification; fresh ephemeral keys and unique
session transcript context do not erase those consequences.

## Review sources

- Official Noise specification, revision 34:
  <https://github.com/noiseprotocol/noise_spec/blob/v34/noise.md>
- Official revision 30-to-34 comparison:
  <https://github.com/noiseprotocol/noise_spec/compare/v30...v34>
- Pinned upstream Noise-C revision:
  <https://github.com/rweather/noise-c/tree/cfe25410979a87391bb9ac8d4d4bef64e9f268c6>
