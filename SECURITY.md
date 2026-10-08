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

The current implementation does not yet satisfy the complete threat model.
Noise IK authenticates adjacent peer identities, but possession of a NetworkID
must not be treated as authorization to join the mesh.

## Current Security Properties

The implementation currently provides the following limited properties:

- Session payloads use ChaCha20-Poly1305 with the packet header as additional
  authenticated data.
- Session handshakes use `Noise_IK_25519_ChaChaPoly_BLAKE2s`, require the
  initiator to name the expected responder static key, authenticate the
  initiator static key, and derive directional keys from Noise `Split()`.
- Initiator-selected session IDs come from OpenSSL's operating-system-seeded
  CSPRNG and are checked against active and pending local sessions.
- Newly created NetworkIDs come from the same checked CSPRNG and network
  creation fails rather than falling back to predictable bytes.
- File-transfer IDs are non-zero values from the checked CSPRNG; a random
  generation failure aborts the transfer before any frame is sent.
- STUN transaction IDs come from the checked CSPRNG; discovery fails closed
  when secure randomness is unavailable.
- The canonical NetworkID, wire version, session ID, roles, and INIT/RESP
  headers are bound into the Noise transcript. Handshake application payloads
  are prohibited.
- Security-critical OpenSSL digest and public-key extraction results are
  checked; failures abort before installing session or onion keys or accepting
  a persisted identity.
- Static and ephemeral private keys, DH outputs, session keys, derived onion
  keys, and intermediate session KDF values use cleansing storage that erases
  owned copies on destruction, overwrite, and move.
- Session, peer-liveness, rekey, session-ID, and file-transfer-ID state accepts
  injected clocks and random sources for deterministic protocol tests.
- Handshake-v2 frames use bounded network-byte-order codecs and reject wrong
  versions, types, flags, lengths, session IDs, truncation, and trailing bytes
  before installing session state. There is no handshake-v1 fallback.
- Common packet headers and complete discovery presence payloads use the
  bounded codec and canonical network byte order; session frames reject
  noncanonical reserved/flag fields and oversized plaintext.
- File-transfer header and chunk payloads use dedicated bounded codecs,
  canonical network byte order, exact declared lengths, and complete frame
  consumption before transfer state is modified.
- File transfers are limited to 1 GiB with 255-byte Windows-safe basenames.
  Traversal separators, control/invalid characters, trailing dots/spaces, and
  reserved device names are rejected. Chunk IDs, indices, counts, and exact
  per-position payload sizes must agree with the authenticated header.
- File chunk sizes are carried in the authenticated transfer header and must
  fit the receiver's local overlay MTU. Senders derive them from the smaller
  of the overlay MTU and the 4 KiB session-plaintext limit after subtracting
  the file-chunk envelope.
- Incoming transfer state is keyed by `(authenticated sender NodeID, transfer
  ID)`. A bounded receipt bitmap ensures duplicate chunks neither rewrite file
  data nor advance completion, and failed disk writes are not marked received.
- File headers and chunks use authenticated selective ACK ranges. Senders keep
  at most 32 chunks in flight per recipient, derive retransmission deadlines
  from observed RTT, ignore ambiguous RTT samples after retransmission, and
  fail after five retries instead of retrying indefinitely.
- The authenticated header commits to a whole-file SHA-256 digest. Receivers
  write to a transfer-unique `.part` path, require the exact declared length
  and digest, and atomically rename to the safe final name only after both
  checks succeed. Verification or rename failure is not acknowledged complete.
- STUN requests and responses use bounded codecs with exact declared lengths;
  the full padded attribute list is validated before accepting an address.
- Endpoint candidate lists are session-encrypted, capped at eight entries,
  reject duplicate or non-unicast IPv4 endpoints, and are scoped to the
  authenticated sender or a peer-observed report about the receiver.
- UDP punch challenges and responses are session-encrypted. A response can
  nominate an endpoint only when its random transaction, authenticated peer,
  source address, and five-second deadline match bounded pending state.
- Established sessions periodically revalidate the active endpoint and
  candidate alternatives. A missed refresh does not clear or replace the
  existing endpoint; promotion still requires the matching authenticated
  response from the exact candidate source.
- AEGIS1 invite payloads use bounded codecs, canonical base64url, exact name
  lengths, exact frame consumption, and valid IPv4 prefix lengths.
- Session data has a 2,048-packet replay window.
- Onion layers use bounded envelope/plaintext framing, ChaCha20-Poly1305, and a
  distinct static-DH-derived key for each source/hop pair.
- Peer-table gossip omits physical endpoints.
- Peer-table merge rejects public keys that do not hash to their advertised
  NodeID, and peer upserts do not replace established non-empty identity keys.
- Peer-table wire encoding and decoding bound the frame size, advertised peer
  count, path length, and prefixes per peer.
- NetworkID mismatches are rejected during the handshake.
- If both peers initiate concurrently, the lower-NodeID initiation wins; the
  losing pending state is destroyed so both peers converge on one session ID.
- Incomplete initiator handshakes expire after 15 seconds; maintenance and
  handshake entry points destroy expired Noise state.
- Authenticated INIT fingerprints remain in a two-minute replay cache that is
  independent of active-session teardown.
- Pending initiator, active session, and retired rekey state each have a hard
  256-entry cap. New peers and initiations fail closed at capacity; rekeys can
  still replace an active session and evict the retired entry nearest expiry.
- Unauthenticated handshake INIT processing is limited to 8 attempts per
  source IP and 64 attempts globally per one-second fixed window. Source
  tracking is capped at 1024 IPs and occurs before payload allocation or Noise
  processing.
- Responders require a stateless HMAC-BLAKE2s retry cookie before Noise DH or
  peer/session allocation. Cookies bind the source IP and port, session ID, and
  exact INIT transcript; secrets rotate every two minutes and the immediately
  previous secret remains valid across one rotation boundary.

These properties do not provide membership authorization or route-origin
authentication.

## Peer Identity Merge Contract

The peer table uses a NodeID as the index for one static X25519 public key. At
the gossip trust boundary, the following rules apply in order:

1. Entries for the receiving node and the adjacent sender are ignored.
2. The public key must be nonzero and its 32-byte BLAKE2b digest must equal the
   advertised NodeID. Invalid bindings cannot modify peer or route state.
3. A NodeID without a local entry may be inserted as an untrusted,
   endpoint-less peer, subject to the 256-peer capacity limit.
4. A legacy empty-key placeholder may acquire its first validated key exactly
   once. A non-empty binding is immutable; a different key rejects the entire
   peer update and its routes.
5. Gossip cannot demote a locally trusted peer or supply a physical endpoint.
6. Routes are considered only after the identity update succeeds. Invalid or
   looping paths install no routes, direct routes are not downgraded, and the
   routing table is capped at 2,048 entries and eight candidates per prefix.

Peer-table frames are limited to 60 KiB, 128 advertised peers, eight path hops
per peer, and 16 prefixes per peer. The decoder requires complete frame
consumption, canonical network-byte-order integers, and zero-valued reserved
flags. Merge results separately report accepted identities, changed peer
bindings, installed routes, malformed data, stale sequences, identity
conflicts, and capacity rejection. Version-3 prefix records include a nonzero
origin sequence, a 1–600 second lease, and a bounded metric. The origin is
bound to the advertised NodeID, the advertiser to the authenticated adjacent
sender, and validation time to the receiver's monotonic clock. These fields
remain hop-authenticated rather than origin-signed.

These checks bind a public key to its self-certifying NodeID. Noise IK also
proves control of that key for an adjacent session. Neither mechanism
establishes prefix ownership or proves that an advertised route exists.

Identity objects now carry a distinct Ed25519 keypair and a signature binding
the current X25519 Noise public key. Version-1 credential files persist these
keys and the signature; legacy 32-byte X25519 files are migrated while
preserving their existing NodeID. The signature is not transmitted in
peer-table/handshake frames, so network identity remains X25519-based and the
local binding alone does not strengthen remote peer authentication.

## Known Critical Limitations

### Peer authentication is not membership authorization

Noise IK proves control of the static X25519 key whose BLAKE2b digest is the
adjacent peer's NodeID. It provides transcript authentication, responder key
confirmation, fresh ephemeral contributions, and directional transport keys.
Rekeying repeats the complete authenticated protocol with a new session ID.

NetworkID remains a cleartext mesh selector and bearer membership credential.
An authenticated static identity is therefore not automatically an authorized
identity: signed, expiring, revocable membership grants and identity rotation
remain future work. The current responder may admit a previously unknown peer
that knows the NetworkID, subject to peer-table capacity.

### Gossip identity binding is enforced, but route ownership is not

Peer-table merge now requires `NodeID = BLAKE2b(public_key)` before an entry can
modify peer or route state. Established non-empty peer keys are immutable
through `PeerManager::upsert`, closing the direct public-key substitution path.

This does not prove that the advertising member owns a prefix or is telling the
truth about a path. All-zero public keys are rejected explicitly. Observable
identity conflicts reject the complete peer update, return a distinct result,
and emit a local security log. Persistent peer and route tables have hard
capacity limits. Gossip merge reports accepted identities, malformed data,
identity conflicts, capacity drops, and installed state separately.
Deterministic eviction remains incomplete. Wire-level peer counts, path
lengths, prefix counts, and decoded bytes are bounded.

Peer and session read APIs return owned metadata snapshots copied while holding
their manager mutexes. Callers cannot retain pointers into internal maps or
mutate records after a lock is released. Session keys, send counters, and
receive replay windows remain private; encryption and decryption serialize
their lookup and state mutation with session removal and rekey.

### Onion forwarding has weaker privacy than the README previously claimed

Every relay frame contains the onion source NodeID outside the onion blob, but
inside the adjacent session. Each relay therefore learns the logical source
NodeID and its next hop. Packet length and timing are not padded.

Onion keys are static per source/hop pair and are not forward-secret. The onion
nonce counter is process-local and resets after a restart, so nonce persistence
must be fixed before the construction can be considered safe for long-lived
static keys.

### Handshake and table state are vulnerable to resource exhaustion

A stateless retry cookie and fixed-window limiter protect unauthenticated INIT
processing before Noise DH; pending initiator, active-session, and
retired-session state have hard caps; incomplete initiator state has a
15-second TTL; authenticated INIT fingerprints have a two-minute replay
window; and peer and route tables are capped. The replay cache and other state
are not yet comprehensively bounded. Peer-table wire limits also prevent
oversized gossip frames from allocating without bound.

### Packets are MTU-bounded but reliability is not provided

The adapter MTU is reduced for the configured underlay MTU and maximum route
depth, and transport rejects oversized outbound and inbound UDP payloads. The
complete contract and overhead budget are documented in the
[overlay MTU policy](README.md#overlay-mtu-policy).
The tunnel rejects oversized, malformed, truncated, and trailing-byte inner
IPv4 packets before Wintun injection and reports drop counters. The overlay
does not fragment or reassemble packets.

Transport send queues have separate per-destination and global control/data
item and byte bounds with a drop-new policy. Handshake and keep-alive traffic
has reserved capacity and strict dequeue priority. Forwarded relay traffic has
per-authenticated-sender and global packet/byte token buckets, with bounded
peer state and idle expiry. There is no originating-traffic pacing or adaptive
backpressure. UDP packet loss is not repaired for general tunnel traffic.

### File transfer is bounded and integrity checked

File transfer acknowledges and retransmits MTU-sized chunks, restores received
ranges when a header is retried, and verifies the exact size and whole-file
digest before publication. Authenticated cancellation stops either direction;
idle transfers expire after five minutes and incomplete `.part` files are
removed. Concurrent transfers and declared disk reservations are capped per
peer and globally. These controls provide bounded reliability, not congestion
control or guaranteed delivery after retry exhaustion.

### Routing path health has bounded failover but limited diagnosis

Learned routes retain bounded alternatives, carry sequence, lease, metric,
origin, advertiser, and local validation-time metadata, and are removed when
their monotonic lease expires. Configured direct routes are not lease-expired.
Direct and relay candidates receive end-to-end challenges every 30 seconds
(relay challenges are onion-carried). Responses
are accepted only for a bounded outstanding random token, matching destination
and route sequence, within five seconds; successful RTT and validation time are
recorded on the exact candidate. A timeout suppresses that exact candidate and
selection immediately falls through to another viable route. Probing resumes
after a 30-second hold-down, and only a later successful response restores
eligibility; same-sequence gossip refreshes preserve the failed state. This
prevents a dead preferred path from remaining selected and limits rapid
failover oscillation. A failed configured direct path is suppressed too, so a
viable learned relay circuit can carry traffic; the direct path is retried
after hold-down. Circuits still obey the configured hop-depth limit, MTU
budget, and authenticated-sender/global forwarding quotas.

There is still no authenticated withdrawal or unreachable error. End-to-end
timeout cannot identify the failing middle hop, so other candidates containing
that hop remain eligible. Selection is primarily based on prefix and hop
count; metric, probe RTT, observed loss, and relay load are not yet scored.

### NAT traversal is incomplete

STUN discovery runs through the already-bound mesh transport socket, so the
reported server-reflexive mapping belongs to the port used for peer traffic.
The synchronous startup exchange accepts a response only from the resolved
server endpoint with the outstanding random transaction ID. Established peers
exchange bounded host, server-reflexive, and peer-observed candidates inside
authenticated session frames. A legitimate member can still lie about a
candidate, so exchanged addresses are retained as unvalidated alternatives
until coordinated authenticated UDP punching succeeds. Punch responses are
bound to a random transaction, the expected peer and candidate source, and a
five-second deadline; concurrent attempts are capped, each peer's punch round
is throttled to 30 seconds, and established bindings/candidates are refreshed
every 30 seconds. This supports endpoint-independent and some
address-dependent mappings, but symmetric NAT and restrictive firewalls still
need relay fallback. Candidate exchange and punching do not authenticate
ownership of an address against a malicious authorized peer.

The `/peers` path label is local routing/session state, not a remote attestation:
`Direct` and `Hole-punched` record the most recently validated adjacent
endpoint path, while `Relayed` means a viable learned relay route exists for
that peer. It does not prove that every packet is currently using that path.

The deterministic NAT simulator covers endpoint-independent mappings that
permit direct punching and destination-specific symmetric mappings that do
not. In the latter case, tests verify route selection falls back to an
authenticated onion circuit. This model does not emulate operating-system NAT
timeouts, packet loss, hairpin behavior, or vendor-specific filtering.

### Credential lifecycle is incomplete

- Secret key material is not consistently zeroized.
- Rotation certificates can be generated and verified against a pinned prior
  Ed25519 key, but are not yet persisted, distributed, or accepted by peers;
  operational key rotation is not available.
- AEGIS1 invites have no signature, expiry, capability restriction, or
  revocation. Config-based AEGIS2 joins validate the bounded, domain-separated
  grant signature, time window, known capabilities, and required join
  capability. Interactive invite commands still consume AEGIS1. Issuer trust
  configuration, revocation enforcement, and application of granted prefixes
  to local address policy remain incomplete. The embedded signing key is not
  itself a trust anchor.
- Signed revocation notices are bounded, signature-checked, and propagated
  over encrypted sessions using the issuer key supplied in an AEGIS2 config
  grant. The initial grant/key still requires out-of-band trust. Active
  sessions are not bound to enrollment nonces, so notices do not yet enforce
  disconnect or deny access.
- Session plaintext now carries an authenticated logical length and random
  padding to 64-byte size buckets. This reduces payload-size precision but
  does not hide packet timing, volume, or the selected size bucket. Packet
  version 2 is fail-closed against older version-1 peers.
- The overlay is IPv4-only.

### LAN discovery is unauthenticated

Presence broadcasts can be forged. The current endpoint self-healing path may
accept a spoofed candidate for a known trusted NodeID, causing connection
attempts and denial of service. Discovery endpoints must be treated as
untrusted candidates until an authenticated handshake validates them.

## Operational Guidance

Given the remaining authorization, onion-nonce, routing, and NAT-traversal
limitations:

- Do not use Aegis for sensitive or production traffic.
- Do not expose its UDP listener directly to the public Internet.
- Run only in an isolated test network with disposable identities and data.
- Treat all peers that know the NetworkID as potentially malicious.

## Reporting Security Issues

Do not include private keys, invite codes, NetworkIDs, packet captures, or other
sensitive deployment data in a public report. Provide a minimal reproduction,
the affected revision, and the observed impact through a private maintainer
contact when one is available.
