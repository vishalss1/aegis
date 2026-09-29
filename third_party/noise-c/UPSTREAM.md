# Noise-C Snapshot Manifest

- Upstream: <https://github.com/rweather/noise-c>
- Commit: `cfe25410979a87391bb9ac8d4d4bef64e9f268c6`
- Commit date: 2023-12-07
- License: MIT; preserved verbatim in `LICENSE`

This is a reduced source snapshot for
`Noise_IK_25519_ChaChaPoly_BLAKE2s`. It retains:

- the public `include/noise/protocol` API;
- the Noise handshake, symmetric, cipher, hash, DH, pattern, name, random, and
  utility state implementations;
- the reference ChaChaPoly, Curve25519, and BLAKE2s backends;
- their required BLAKE2s, ChaCha20, Poly1305, Curve25519-donna, and
  Ed25519-donna support headers/sources; and
- the upstream SHA-256 utility used only by Noise-C's public-key fingerprint
  helper (not as an enabled handshake hash backend).

The snapshot has two Aegis-authored compatibility sources. `unsupported.c`
makes constructors for unretained algorithms return null, so the generic
upstream factories link without accidentally exposing algorithms outside the
selected suite. `aegis.c` and its `aegis.h` declaration provide a narrow,
ChaChaPoly-only export hook that copies split keys out of the pinned reference
backend before all Noise-C state is destroyed.

The snapshot intentionally excludes Autotools files, examples, tools, upstream
tests, signing support, AES-GCM, Curve448, NewHope, BLAKE2b, and optional SHA-2
backends. The generic upstream pattern table is retained; the Aegis wrapper
will expose only IK. The authoritative
compiled-file manifest is `NOISE_C_SOURCES` in `CMakeLists.txt`.

Do not update individual upstream files. Import a reviewed commit as one change,
update this manifest and `DEPENDENCIES.md`, and rerun the official vector gate.
The compatibility assessment against Noise revisions 31 through 34 is recorded
in `REVISION_REVIEW.md` and must be repeated for any dependency update.
