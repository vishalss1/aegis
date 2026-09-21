# Security Status

Aegis is an experimental networking prototype. It is not ready for production
use or for protecting sensitive traffic. The code exercises encrypted sessions,
mesh gossip, and onion-style forwarding, but several security invariants required
by that design are not implemented yet.

This document describes the behavior of the current code. It is intentionally
more conservative than the target architecture.

## Threat Model

The intended threat model assumes that the network, endpoints advertised over
the LAN, and other mesh members may be hostile. A complete design must therefore
authenticate peers, bind public keys to NodeIDs, limit resource use, and treat
all received protocol fields as untrusted.

The current implementation does not yet satisfy that threat model. In
particular, possession of a NetworkID must not be treated as proof of a peer's
identity.

## Current Security Properties

The implementation currently provides the following limited properties:

- Session payloads use ChaCha20-Poly1305 with the packet header as additional
  authenticated data.
- Session keys are derived from fresh ephemeral X25519 keys.
- Session data has a 2,048-packet replay window.
- Onion layers use ChaCha20-Poly1305 and a distinct static-DH-derived key for
  each source/hop pair.
- Peer-table gossip omits physical endpoints.
- Peer-table merge rejects public keys that do not hash to their advertised
  NodeID, and peer upserts do not replace established non-empty identity keys.
- Peer-table wire encoding and decoding bound the frame size, advertised peer
  count, path length, and prefixes per peer.
- NetworkID mismatches are rejected during the handshake.

These properties do not compensate for the missing peer authentication and
route-origin authentication described below.

## Known Critical Limitations

### Sessions do not authenticate peers

The handshake transmits a session ID, ephemeral public key, claimed NodeID, and
NetworkID in cleartext. Key derivation uses only ephemeral-to-ephemeral X25519.
The static identity key neither authenticates the transcript nor contributes to
the session secret.

Consequences:

- A mesh member can claim another member's NodeID.
- An active attacker can impersonate an expected peer.
- There is no handshake key-confirmation tag.
- NetworkID is a mesh selector or bearer value, not peer authentication.
- Rekeying repeats the same unauthenticated protocol.

The planned replacement is a versioned Noise IK handshake with no downgrade to
the existing format.

### Gossip identity binding is enforced, but route ownership is not

Peer-table merge now requires `NodeID = BLAKE2b(public_key)` before an entry can
modify peer or route state. Established non-empty peer keys are immutable
through `PeerManager::upsert`, closing the direct public-key substitution path.

This does not prove that the advertising member owns a prefix or is telling the
truth about a path. All-zero public keys are rejected explicitly. Observable
identity conflicts reject the complete peer update, return a distinct result,
and emit a local security log. Persistent peer and route tables have hard
capacity limits, while structured merge results and deterministic eviction
remain incomplete. Wire-level peer counts, path lengths, prefix counts, and
decoded bytes are bounded.

### Onion forwarding has weaker privacy than the README previously claimed

Every relay frame contains the onion source NodeID outside the onion blob, but
inside the adjacent session. Each relay therefore learns the logical source
NodeID and its next hop. Packet length and timing are not padded.

Onion keys are static per source/hop pair and are not forward-secret. The onion
nonce counter is process-local and resets after a restart, so nonce persistence
must be fixed before the construction can be considered safe for long-lived
static keys.

### Handshake and table state are vulnerable to resource exhaustion

There is no stateless retry cookie, handshake replay cache, strict session-table
capacity, or per-source handshake rate limit. Peer and route tables are capped,
but retired-session and other gossip-derived state are not comprehensively
bounded or expired. Peer-table wire limits also prevent oversized gossip frames
from allocating without bound.

### MTU and reliability are not managed

The adapter MTU is not reduced for session and onion overhead, and the overlay
does not fragment or reassemble packets. Large IP packets can exceed the path
MTU and be lost.

The transport has no bounded per-peer queues, congestion pacing, relay quotas,
or backpressure. UDP packet loss is not repaired for general tunnel traffic.

### File transfer is not reliable or safe for hostile input

File transfer sends 32 KiB chunks with a fixed delay and no acknowledgement,
retransmission, completion digest, or resume support. Completion is based on a
received-chunk counter rather than a verified chunk set. Transfer state is
process-global, and received filenames are not yet handled as hostile path
input.

### Routing does not validate path liveness

Learned routes have no lease, expiry, path probe, link metric, or authenticated
withdrawal. A failed middle hop can leave a route blackholed until later gossip
happens to replace it. Route selection is primarily based on prefix and hop
count.

### NAT traversal is incomplete

STUN discovers a mapping using a separate socket, the mapping is not exchanged
through an authenticated candidate protocol, and there is no coordinated hole
punching or relay-of-last-resort circuit for symmetric NAT.

### Credential lifecycle is incomplete

- Secret key material is not consistently zeroized.
- Static identities have no authenticated rotation mechanism.
- AEGIS1 invites have no signature, expiry, capability restriction, or
  revocation.
- The overlay is IPv4-only.

### LAN discovery is unauthenticated

Presence broadcasts can be forged. The current endpoint self-healing path may
accept a spoofed candidate for a known trusted NodeID, causing connection
attempts and denial of service. Discovery endpoints must be treated as
untrusted candidates until an authenticated handshake validates them.

## Operational Guidance

Until the authenticated handshake, persistent state limits, and MTU policy are
implemented:

- Do not use Aegis for sensitive or production traffic.
- Do not expose its UDP listener directly to the public Internet.
- Run only in an isolated test network with disposable identities and data.
- Treat all peers that know the NetworkID as potentially malicious.
- Do not rely on file transfer for data integrity or complete delivery.

## Reporting Security Issues

Do not include private keys, invite codes, NetworkIDs, packet captures, or other
sensitive deployment data in a public report. Provide a minimal reproduction,
the affected revision, and the observed impact through a private maintainer
contact when one is available.
