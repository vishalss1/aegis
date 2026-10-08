<div align="center">

# 🛡️ AEGIS

### Windows-Native Secure Overlay Network Mesh

An experimental, user-space **encrypted overlay network** built in **C++** — exploring identity-based routing, multi-hop onion relaying, mesh bootstrapping, peer gossip, and session rekeying.

[![Build](https://github.com/vishalss1/aegis/actions/workflows/build.yml/badge.svg)](https://github.com/vishalss1/aegis/actions/workflows/build.yml)
![C++20](https://img.shields.io/badge/C++20-MSVC-00599C?style=flat&logo=cplusplus)
![Windows](https://img.shields.io/badge/Windows-Native-0078D6?style=flat&logo=windows)
![OpenSSL](https://img.shields.io/badge/OpenSSL-EVP-721412?style=flat)
![Wintun](https://img.shields.io/badge/Wintun-0.14.1-555555?style=flat)
![CMake](https://img.shields.io/badge/CMake-3.20+-064F8C?style=flat&logo=cmake)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)

</div>

---

## Table of Contents

[Security Status](#security-status) · [What Is Aegis](#what-is-aegis) · [Engineering Decisions](#engineering-decisions) · [Architecture](#architecture) · [Features](#features) · [Onion Security Model](#onion-security-model) · [CI/CD](#cicd-pipeline) · [Tech Stack](#tech-stack) · [Quick Start](#quick-start) · [Usage](#usage) · [Config Format](#configuration-file) · [MTU Policy](#overlay-mtu-policy) · [Testing](#testing)

---

## Security Status

> [!WARNING]
> Aegis is an experimental prototype and is not ready to protect sensitive or
> production traffic. Adjacent sessions now authenticate static peer identities
> with Noise IK, and gossip enforces the NodeID/public-key binding at its merge
> boundary, but membership authorization, route ownership, and reliability
> protections remain incomplete. See
> [SECURITY.md](SECURITY.md) for the current guarantees and known limitations.

---

## What Is Aegis

Most VPNs stop at "two endpoints, one encrypted tunnel." Aegis explores a decentralized mesh in which nodes are addressed by public-key-derived identifiers. Adjacent sessions authenticate those identifiers with Noise IK. Traffic between non-adjacent nodes can be onion-wrapped, but relays still observe the logical source NodeID, adjacent hops, packet sizes, and timing.

Built as a Windows-native CLI binary that creates a Wintun virtual adapter, Aegis routes overlay traffic through a fully layered stack:

```
Identity  →  Session (Noise IK handshake)  →  Routing (prefix → next-hop → peer)
→  Onion Wrapping (ChaCha20-Poly1305 layers)  →  UDP (Winsock)  →  Internet
```

A VPN point-to-point tunnel is only the first application of this overlay. The mesh is the product.

---

## Engineering Decisions

A few design choices that shaped how Aegis works.

**NodeID, not IP, is the intended identity.** In the current wire-compatible phase, each node still derives `NodeID` as `BLAKE2b(X25519 public key)`. Identity objects also hold a separate Ed25519 signing key that signs a domain-separated binding to the Noise X25519 key. Version-1 credential files persist both private keys and the binding; exact legacy 32-byte X25519 files are migrated without changing their NodeID. The signer/binding is not yet carried on the wire, so peer-table merge and Noise IK still enforce the legacy X25519-derived NodeID contract.

Identity rotation certificates can now be created and verified: the prior Ed25519 key signs both identities' X25519 bindings and the transition timestamp. Verification requires the expected prior signing key as a trust anchor. Certificates are not yet persisted, distributed, or consumed by peers, so this is a cryptographic primitive rather than operational rotation.

Signed membership revocation notices can be stored and propagated over encrypted peer sessions. Config-based AEGIS2 joins use the issuer key from the supplied grant as the revocation authority; that initial key still requires out-of-band trust. Notices are bounded and signature-checked, but sessions are not yet associated with enrollment nonces, so receiving a revocation does not yet disconnect or reject a member.

**AEGIS2 grants are signed and validated in config-based joins.** AEGIS2 defines a bounded canonical membership-grant payload signed with the issuer's Ed25519 key, including enrollment nonce, validity timestamps, capability bits, allowed IPv4 prefixes, bootstrap candidates, and revocation epoch. Config-based startup validates the signature, current time window, known capabilities, and required join capability before adding bootstrap candidates. The embedded issuer key is not a trust anchor; callers must pin/authorize it. Revocation enforcement and applying granted prefixes to local address policy remain planned. Interactive invite commands still use AEGIS1, a separate unsigned legacy format.

**Onion routing is a core requirement, not a stretch goal.** Each hop decrypts one `ChaCha20-Poly1305` layer keyed by `SHA256("aegis-onion-v1" ‖ X25519(our_priv, source_pub))`. The current framing exposes the source NodeID to every relay and does not pad length or timing, so it should not yet be treated as a complete anonymity system.

**A mesh with no fixed entry point.** Nodes are provisioned with a list of bootstrap candidates via out-of-band config. Joining follows an availability-based policy — each candidate gets its own background connect loop with exponential backoff. The node comes up and starts routing immediately even if zero peers are reachable. Whichever candidate becomes available first is used; no node is a server.

**Peer table gossip with IP-stripping.** Once a session exists, every node sends bounded peer-table deltas so the mesh converges without repeating unchanged entries. Periodic full resynchronization repairs lost UDP deltas. Endpoints are omitted from gossip, which limits physical-address propagation. Gossip validates advertised NodeID/public-key bindings, but does not authenticate prefix ownership, path origin, or the advertising member's honesty.

**NetworkID gates sessions, not discovery.** A mismatched NetworkID is rejected before a session is created. NetworkID is currently sent in cleartext and must be treated as a mesh selector or bearer value, not peer authentication. LAN presence broadcasts are unauthenticated and network-agnostic.

**Layered packet processing.** The Packet Engine separates IP parsing, session framing, relay wrapping, and UDP transport. Shared packet headers, handshake payloads, discovery, gossip, STUN, invites, onion layers, and file-transfer payloads use bounded typed codecs with exact-length validation.

**Rekeying without a new packet type.** Session rekeying is a fresh authenticated Noise IK handshake with a new session ID — identical to initial connection. The prior session is retired into a 10-second grace window so in-flight packets under the old key still decrypt cleanly. The lower-NodeID peer drives rekeying every 120 seconds. Replay windows and sequence numbers restart per session ID.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Applications                            │
│          (any app using the OS TCP/IP stack — unmodified)        │
└────────────────────────────┬─────────────────────────────────────┘
                             │ IP packets (IPv4)
                   ┌─────────┴──────────┐
                   │   Windows TCP/IP   │
                   │       Stack        │
                   └─────────┬──────────┘
                             │
                   ┌─────────┴──────────┐
                   │   Wintun Adapter   │   Virtual NIC — reads outbound,
                   │  (kernel driver)   │   injects inbound IP packets
                   └─────────┬──────────┘
                             │
         ┌───────────────────┴──────────────────────────┐
         │                Aegis Overlay Stack           │
         │                                              │
         │  ┌───────────────────────────────────────┐   │
         │  │          Packet Engine                │   │
         │  │  IPv4 parse/validate · layer typing   │   │
         │  │  IP Packet → Encrypted Frame          │   │
         │  │  Encrypted Frame → Relay Payload      │   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Routing Engine               │   │
         │  │  prefix → next-hop → peer (NodeID)    │   │
         │  │  Direct + retained relay candidates   │   │
         │  │  Loop detection · bounded alternatives│   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Session Manager              │   │
         │  │  Noise IK handshake · rekeying        │   │
         │  │  ChaCha20-Poly1305 · replay windows   │   │
         │  │  NetworkID gate · grace-window retire │   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Peer Manager                 │   │
         │  │  NodeID-indexed peer table            │   │
         │  │  Endpoint tracking · health state     │   │
         │  │  Peer table gossip (no IP in wire)    │   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Identity Module              │   │
         │  │  NodeID = BLAKE2b(PublicKey)          │   │
         │  │  Static X25519 keypair · NetworkID    │   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Transport Layer              │   │
         │  │  Winsock UDP · keep-alives            │   │
         │  │  Bounded per-peer tx · background I/O │   │
         │  └───────────────┬───────────────────────┘   │
         └──────────────────┼───────────────────────────┘
                            │ Encrypted UDP datagrams
                   ┌────────┴───────────┐
                   │   UDP / Winsock    │
                   └─────────┬──────────┘
                             │
                         Internet
```

### Onion Relay Path (v2+ mesh)

```
  Node A  ──────────────────────────────────────────────►  Node D
          session(A→B)      session(B→C)     session(C→D)
          ┌────────────┐   ┌────────────┐   ┌────────────┐
          │ TYPE_RELAY │   │ TYPE_RELAY │   │ TYPE_RELAY │
          │ Layer B    │   │ Layer C    │   │ inner = IP │
          │  (enc→B)   │   │  (enc→C)   │   │ next=0x00  │
          └────────────┘   └────────────┘   └────────────┘
          B sees: A, C     C sees: B, D     D injects IP
          B never sees D   C never sees A
```

### Data Flow

| Channel | Direction | Description |
|:--------|:----------|:------------|
| Wintun ring | App → Overlay | Outbound IP packet capture |
| Wintun ring | Overlay → App | Inbound IP packet injection |
| UDP (TYPE_DATA) | Peer ↔ Peer | Direct encrypted tunnel — adjacent nodes |
| UDP (TYPE_RELAY) | Hop ↔ Hop | Onion-wrapped relay frame — non-adjacent nodes |
| UDP (TYPE_HANDSHAKE_INIT/COOKIE/RESP) | Peer ↔ Peer | Stateless endpoint retry, then X25519 key agreement |
| UDP (TYPE_KEEPALIVE) | Peer ↔ Peer | Empty encrypted frame — liveness + NAT keepalive |
| UDP (TYPE_PEER_TABLE) | Peer ↔ Peer | Gossip — NodeID + pubkey + prefix sequence/lease/metric records (no endpoints) |
| UDP (TYPE_PATH_PROBE / TYPE_RELAY) | End ↔ End | Authenticated route challenge/response, direct or onion-relayed |
| UDP (TYPE_ENDPOINT_CANDIDATES) | Peer ↔ Peer | Encrypted, bounded host/server-reflexive/peer-observed candidate exchange |
| UDP (TYPE_DISCOVERY) | LAN broadcast | Presence — NodeID + NetworkID + endpoint (pre-session) |

---

## Features

| Feature | What It Does |
|:--------|:-------------|
| **NodeID Addressing** | Peers are addressed as `NodeID = BLAKE2b(PublicKey)`. Received gossip enforces that binding, and Noise IK authenticates it for adjacent sessions. |
| **Noise IK + ChaCha20-Poly1305** | Authenticated Noise IK derives directional session keys with fresh ephemerals and transcript key confirmation; ChaCha20-Poly1305 authenticates data frames. |
| **Bounded Handshake Admission** | Per-IP/global INIT limits and rotating stateless retry cookies prove endpoint reachability before responder-side Noise DH or peer/session allocation. |
| **Bounded Transport Queues** | Separate control/data item and byte caps bound outbound UDP memory. Handshakes and keep-alives use reserved control capacity and drain first; peers within each class drain round-robin. |
| **Relay Forwarding Quotas** | Per-authenticated-sender and global packet/byte token buckets bound forwarded relay traffic. Idle quota state expires and total tracking is capped at 256 peers. |
| **Reliable File Windows** | File headers and chunks use authenticated selective acknowledgements, a 32-chunk sliding window, RTT-derived retransmission deadlines, bounded retry counts, resume ranges, and explicit cancellation. Idle transfers expire after five minutes; per-peer and global transfer/disk reservations are capped. |
| **Verified File Commit** | Receivers write to transfer-unique `.part` files, verify the authenticated whole-file SHA-256 digest and exact size, then atomically rename into place. |
| **Multi-hop Onion Routing** | Each hop decrypts one layer and learns the next hop. Relays also receive the source NodeID, and unpadded packet size and timing remain visible. |
| **Bounded Route Candidates and Circuit Fallback** | Each prefix retains up to eight distinct destination/next-hop candidates instead of overwriting alternatives. Direct and learned relay routes receive bounded 30-second end-to-end probes with authenticated responses and RTT observations. A timeout suppresses only that route, falling back to another viable route (including a bounded onion circuit) and resumes probing after a 30-second hold-down; only a later success restores the route. Relay paths remain capped by `max_relay_depth` and forwarding quotas. |
| **Peer Table Gossip** | Full mesh convergence without a coordinator. Version-3 prefix records carry origin sequence, bounded lease, and metric metadata; receivers bind the advertiser to the authenticated adjacent sender and reject older learned sequences. Changes fan out as bounded, coalesced per-recipient deltas with periodic full resynchronization. |
| **Identity-Hiding Gossip** | Peer tables carry NodeID + public key + IP prefix routes. Physical endpoints are never transmitted in gossip — non-adjacent nodes cannot learn each other's real IP. |
| **NetworkID Mesh Segmentation** | NetworkID mismatches are rejected before session creation. This separates accidental cross-mesh traffic but is not static peer authentication. |
| **Join-Any-Available Bootstrap** | No fixed entry point, no dedicated server. Each configured candidate gets its own background connect loop with exponential backoff (1s → 30s cap). The node routes immediately; sessions form as peers become reachable. |
| **Session Keep-Alive & Dead Detection** | Keep-alives every 25s. Dead timeout at 180s removes the session and all routes. Configured peers are re-joined automatically on reconnect, routes reinstalled, peer table re-announced. |
| **Transparent Rekeying** | Fresh authenticated Noise IK handshake every 120s driven by the lower-NodeID peer. Prior session retired to a 10s grace window — in-flight packets decrypt cleanly. Replay windows and sequence numbers reset per session ID. |
| **Endpoint Candidates and UDP Punching** | Established peers exchange at most eight encrypted host, server-reflexive, and peer-observed IPv4 candidates, then send simultaneous session-authenticated challenges to those addresses. A matching response must arrive from the challenged endpoint within five seconds before it is nominated as active. The active endpoint and alternatives are re-punched and candidates re-announced every 30 seconds; a failed refresh never displaces the current endpoint. `/peers` reports the last validated direct or hole-punched path, or a viable relayed route. Punch attempts are bounded and throttled; symmetric NAT may still require relay fallback. LAN presence hints remain unauthenticated. |
| **YAML Config Mode** | `--config <file>` — strict YAML subset parser. Validates all fields, rejects unknown keys. Auto-elevates via UAC (`ShellExecuteW "runas"`) when launched without Administrator rights. |
| **Replay Protection** | Per-session sliding window of 2048 sequence numbers. Out-of-window and duplicate sequence numbers are silently discarded. |
| **Layered Packet Processing** | IP parsing, session framing, relay wrapping, UDP transport, and file-transfer payload framing are separate modules with bounded codecs and exact-length validation. File transfers reject unsafe Windows names and inconsistent metadata, key state by authenticated sender plus transfer ID, and count only unique chunks. |

---

## Onion Security Model

```
Hop 1 — Session Encryption (adjacent peers)
         TYPE_RELAY frame is a normal ChaCha20-Poly1305 encrypted packet
         addressed to the immediate next hop. On-path observers see only
         the next-hop session — never the onion innards.

Hop N — Onion Layer Decryption
         Each relay derives:
           layer_key = SHA256("aegis-onion-v1" ‖ X25519(hop_priv, source_pub))
         Decrypts its layer, reads the next_hop NodeID, re-wraps the
         remaining blob under the same source NodeID, forwards to next_hop.
         The relay sees: the source NodeID, its predecessor, its successor,
         and observable packet length and timing.
         The relay does not directly receive the source IP or inner payload.

Final hop — next_hop = 0x00…00
         Source builds the innermost layer with next_hop = all zeros.
         The destination decrypts the last layer and injects the raw
         IP packet directly into its Wintun adapter — no nested frame.

Endpoint propagation rule:
         Endpoints are NEVER sent in TYPE_PEER_TABLE messages.
         A node's real IP is never reachable from gossip alone —
         only from a live direct session that the node itself accepted.
         NodeID/public-key binding is verified during merge. Prefix and
         path ownership are not authenticated.
```

Keys are generated once at node startup (static X25519 keypair). Onion layer keys are static per `(source, hop)` pair and are not forward-secret. Adjacent session keys use authenticated Noise IK with fresh ephemeral keys. See [SECURITY.md](SECURITY.md) before relying on these properties.

---

## CI/CD Pipeline

One pipeline. Must be green on every push to `master` and on every pull request.

**`build.yml`** — Windows x64 Release, runs on `windows-latest`

```
1.  Checkout source
2.  Cache Wintun SDK  (version-keyed, avoids re-download on cache hit)
3.  Download Wintun 0.14.1 from wintun.net  (on cache miss)
4.  Locate or install OpenSSL via Chocolatey
5.  Configure CMake  — WINTUN_DIR, AEGIS_USE_OPENSSL=ON
6.  cmake --build --config Release

    ✅  aegis.exe produced at build\bin\Release\aegis.exe
    ✅  File size logged — zero-byte artifact fails the step
```

---

## Tech Stack

| Domain | Technologies |
|:-------|:-------------|
| **Language** | C++20, MSVC |
| **Build** | CMake 3.20+, `build.bat` convenience wrapper |
| **Crypto** | OpenSSL EVP — X25519, ChaCha20-Poly1305, BLAKE2b, SHA-256 |
| **Virtual Adapter** | Wintun SDK 0.14.1 (`wintun.sys` kernel driver + `wintun.dll` user-space API) |
| **Transport** | Winsock UDP — `<winsock2.h>` |
| **Interface Config** | IP Helper API — `<iphlpapi.h>` |
| **OS Elevation** | Windows UAC — `ShellExecuteW "runas"` |
| **Configuration** | Custom strict YAML subset parser (no external YAML dependency) |
| **CI/CD** | GitHub Actions, `windows-latest`, Chocolatey, CMake |
| **Testing** | CTest unit suite — 25 independent test binaries |

Security-relevant pins and integration constraints are recorded in
[DEPENDENCIES.md](DEPENDENCIES.md). Noise-C is selected there for handshake v2
and is active behind the reviewed Aegis wrapper and vector gate.

---

## Repository Layout

```
aegis/
├── CMakeLists.txt              # CMake root — OpenSSL, Wintun, C++20, CTest
├── build.bat                   # Visual Studio build wrapper (x64 / x86)
├── include/
│   └── aegis/                  # Public C++ headers (mirrors src/ layout)
│       ├── adapter/            # Wintun adapter abstraction
│       ├── config/             # YAML config structs + loader
│       ├── crypto/             # X25519 and ChaCha20-Poly1305 primitives
│       ├── discovery/          # LAN presence broadcasts
│       ├── identity/           # NodeID, NetworkID, static keypair
│       ├── invite/             # AEGIS1 invite code encoder/decoder
│       ├── packet/             # IP packet, encrypted frame, relay payload types
│       ├── peer/               # Peer table, gossip, peer state
│       ├── platform/           # Windows privilege check + UAC elevation
│       ├── routing/            # Route table — prefix → next-hop → peer
│       ├── session/            # Handshake, rekeying, replay window, grace retire
│       ├── stun/               # RFC 5389 STUN Binding Request & mapped address discovery
│       ├── transport/          # UDP I/O, handshake rate limits, retry cookies
│       └── tunnel/             # Typed frame dispatch, tx/rx loops, maintenance
├── src/                        # Implementation .cpp files (mirrors include/aegis/)
│   ├── main.cpp                # CLI entry point — mode dispatch, self-tests
│   ├── adapter/adapter.cpp
│   ├── config/config.cpp
│   ├── crypto/x25519.cpp
│   ├── crypto/chacha20poly1305.cpp
│   ├── discovery/discovery.cpp
│   ├── identity/identity.cpp
│   ├── invite/invite.cpp       # AEGIS1 invite string encoding & decoding
│   ├── packet/packet.cpp
│   ├── packet/relay.cpp        # build_onion / peel_onion
│   ├── peer/peer.cpp
│   ├── peer/peer_table.cpp     # TYPE_PEER_TABLE wire format + merge logic
│   ├── platform/platform.cpp
│   ├── routing/routing.cpp
│   ├── session/session.cpp
│   ├── stun/stun.cpp           # STUN client for WAN endpoint discovery
│   ├── transport/              # UDP transport and handshake admission controls
│   └── tunnel/tunnel.cpp       # tx_loop, rx_loop, maintenance loop
├── tests/                      # CTest unit test suite — 25 binaries
│   ├── test_packet.cpp
│   ├── test_wire.cpp
│   ├── test_handshake_v2.cpp
│   ├── test_noise_dependency.cpp
│   ├── test_noise_ik.cpp
│   ├── test_transport.cpp
│   ├── test_crypto.cpp
│   ├── test_random.cpp
│   ├── test_primitives.cpp
│   ├── test_secret.cpp
│   ├── test_aead.cpp
│   ├── test_identity.cpp
│   ├── test_tunnel.cpp
│   ├── test_session.cpp
│   ├── test_peer.cpp
│   ├── test_routing.cpp
│   ├── test_peer_table.cpp
│   ├── test_relay.cpp
│   ├── test_discovery.cpp
│   ├── test_config.cpp
│   ├── test_invite.cpp
│   ├── test_stun.cpp
│   ├── test_endpoint_candidate.cpp
│   └── test_cli.cpp
│
└── wintun/                     # Wintun SDK (include/ + bin/amd64/ + bin/x86/)
    ├── include/wintun.h
    └── bin/
        ├── amd64/wintun.dll
        └── x86/wintun.dll
```

---

## Quick Start

### Prerequisites

| Requirement | Notes |
|:------------|:------|
| **Windows** (64-bit) | Only supported platform |
| **Visual Studio 2022** | C++ Desktop workload, or standalone MSVC Build Tools |
| **CMake 3.20+** | Available in PATH |
| **OpenSSL** (dev edition) | Default path: `C:\Program Files\OpenSSL-Win64` |
| **Wintun SDK 0.14.1** | [wintun.net](https://www.wintun.net/) — extract to `wintun/` in the project root |
| **Administrator rights** | Required at runtime to create the virtual adapter |

### Build

```cmd
REM Quick build (x64 Release)
build.bat x64
REM Binary output: build\bin\Release\aegis.exe
```

```cmd
REM Manual CMake build
cmake -B build -DWINTUN_DIR="wintun" -DAEGIS_USE_OPENSSL=ON
cmake --build build --config Release
```

---

## Usage

> [!IMPORTANT]
> `aegis.exe` requires **Administrator** privileges to create and configure the Wintun virtual adapter. If launched from an unprivileged console, it will automatically trigger a UAC prompt and relaunch itself elevated.

### Config File Mode

```cmd
aegis.exe --config mesh.yaml
```

### CLI Mode (two-node setup)

```cmd
REM Node A (initiator)
aegis.exe --tunnel 10.10.0.1 24 51820 --network <64-hex-NetworkID>

REM Node B (connects to A)
aegis.exe --tunnel 10.10.0.2 24 51821 ^
  --network <64-hex-NetworkID> ^
  --peer <NodeID-hex> <pubkey-hex> <NodeA-IP> 51820 10.10.0.1/32
```

Full flag reference:

```
aegis.exe --tunnel <local_ip> <prefix> <listen_port>
          [--network <hex64>]
          [--peer <nodeid_hex> <pubkey_hex> <ip> <port> <allowed_cidr> ...]

  --config <file>                             Run from YAML config file. Auto-elevates via UAC.
  --invite generate <netid> <pk> <ep> <cidr> Generate an AEGIS1 invite code string.
  --invite decode <invite_code>               Decode and display an AEGIS1 invite code.
  --tunnel ...                                Start a mesh node from command-line flags.
```

### Diagnostic / Self-Test Modes

Run these without a running mesh — no peers, no adapter needed for most:

```cmd
aegis.exe --crypto-test         # X25519 key generation + shared secret derivation
aegis.exe --aead-test           # ChaCha20-Poly1305 encrypt/decrypt + tamper rejection
aegis.exe --identity-test       # NodeID determinism + NetworkID matching
aegis.exe --session-test        # Handshake, key derivation, replay window, rekey
aegis.exe --peer-test           # Multi-peer table states, endpoints, session lookup
aegis.exe --routing-test        # prefix → next-hop → peer + loop avoidance
aegis.exe --tunnel-test         # Simulated 3-node mesh, bootstrap, UDP round-trips
aegis.exe --gossip-test         # 4-node A-B-C-D chain — gossip must converge full mesh
aegis.exe --segmentation-test   # Two meshes on one host — sessions must not cross
aegis.exe --lifecycle-test      # Keep-alive, dead detection, reconnect, rekey under load
```

Adapter-required diagnostics (needs admin):

```cmd
aegis.exe --listen              # Create 10.10.0.1/24 adapter, print packets for 30s
aegis.exe --ping-test           # Inject loopback UDP, confirm OS TCP/IP receives it
aegis.exe --inject <hex>        # Inject raw hex IP packet, read one reply
aegis.exe --transport-test      # Winsock loopback send/receive verification
```

---

## Configuration File

Aegis uses a strict line-based YAML subset. Unknown top-level sections or unknown keys inside any section are rejected with an error.

```yaml
interface:
  # Overlay IPv4 address and CIDR prefix length for this node's virtual adapter
  address: 10.10.0.1/24
  # Physical UDP port — Winsock binds here for all overlay traffic
  listen_port: 51820
  # Physical IPv4 path MTU used to derive the virtual adapter MTU
  underlay_mtu: 1500
  # Maximum Route::path peer count (1 = direct only, 8 = protocol maximum)
  max_relay_depth: 8
  # Optional STUN server; discovery uses the bound mesh UDP socket (RFC 5389)
  stun_server: stun.l.google.com:19302

identity:
  # 256-bit NetworkID as 64 lowercase hex characters.
  # All nodes in the same mesh must share this value.
  network_id: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
  # Alternatively, supply an AEGIS1 invite code:
  # invite: AEGIS1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyCGqP_u3cy7qgARIjNEVWZ3iJmqu8zd7v8AESIzRFVmdwJxAMtsygIACgog

peer:
  # Each entry is a bootstrap candidate. The node joins whichever
  # candidates are reachable and retries the rest indefinitely.
  - endpoint: 203.0.113.2:51820
    public_key: 86a8ffeeddccbbaa00112233445566778899aabbccddeeff0011223344556677
    allowed_ips:
      - 10.10.0.2/32

  - endpoint: 198.51.100.5:51820
    public_key: aabbccddeeff00112233445566778899aabbccddeeff001122334455667788
    allowed_ips:
      - 10.10.0.3/32
```

**Validation rules:**
- `interface.address` and `interface.listen_port` are required; missing either fails parsing.
- `identity.network_id` must be exactly 64 hex characters if present.
- Each `peer` entry must have both `endpoint` and `public_key`; missing either fails parsing.
- `public_key` must be exactly 32 bytes (64 hex characters).
- `listen_port` must be in range 1–65535.
- `underlay_mtu` must leave at least a 576-byte overlay MTU after framing.
- `max_relay_depth` must be in range 1–8; its worst-case overhead determines
  the Wintun IPv4 MTU.

## Overlay MTU Policy

Aegis uses an explicit MTU contract so an inner IPv4 packet plus all Aegis and
IPv4/UDP framing fits the configured physical path MTU. Aegis does not perform
path-MTU discovery, overlay fragmentation, or overlay reassembly. Packets that
exceed a configured limit are dropped rather than fragmented by Aegis.

`underlay_mtu` is the maximum complete outer IPv4 packet size, including the
outer IPv4 and UDP headers. `max_relay_depth` is the greatest permitted
`Route::path` length: depth 1 is a direct peer, while depths 2 through 8 are
relayed paths that include the destination.

The Wintun IPv4 MTU is calculated at startup from the worst permitted route:

```text
overlay MTU = underlay_mtu - wire overhead(max_relay_depth)
```

Configuration is rejected unless the result is at least IPv4's 576-byte
minimum reassembly size. Session plaintext is now encoded as a two-byte
authenticated logical length, payload, and random padding to a 64-byte bucket.
The session header version is 2; older packet-version peers fail closed. The
worst-case padding allowance means an eight-hop route requires an underlay MTU
of at least 1,226 bytes.

### Wire-overhead calculation

| Component | Bytes | Applies to |
|:--|--:|:--|
| Outer IPv4 header | 20 | Every packet |
| Outer UDP header | 8 | Every packet |
| Encrypted session frame | 109 | Worst case: 44-byte header/nonce/tag + 2-byte logical length + up to 63 padding bytes |
| Relay source NodeID | 32 | Relayed packets only |
| Relay content class | 1 | Relayed packets only: IP packet or path probe |
| Onion layer | 60 per hop | Relayed packets only: 32-byte next hop, 12-byte nonce, 16-byte tag |

For route depth `d`:

```text
direct (d = 1):   wire overhead = 28 + 109 = 137
relayed (d >= 2): wire overhead = 28 + 109 + 33 + (60 * d)
```

With the default 1,500-byte underlay MTU, the complete budget is:

| Route depth | Route type | Wire overhead | Safe overlay MTU |
|--:|:--|--:|--:|
| 1 | Direct | 137 | 1,363 |
| 2 | Relayed | 290 | 1,210 |
| 3 | Relayed | 350 | 1,150 |
| 4 | Relayed | 410 | 1,090 |
| 5 | Relayed | 470 | 1,030 |
| 6 | Relayed | 530 | 970 |
| 7 | Relayed | 590 | 910 |
| 8 | Relayed | 650 | 850 |

The configured Wintun MTU uses the row for `max_relay_depth`. Outbound
processing also checks the resolved route's actual depth before encryption.

### Enforcement and diagnostics

The contract is enforced at several boundaries:

1. Configuration rejects invalid route depths or an underlay/depth combination
   that would produce an overlay MTU below 576 bytes.
2. Wintun is configured with the worst-case overlay MTU so the Windows network
   stack does not normally submit larger inner packets.
3. The tunnel rejects an outbound inner packet that exceeds the budget for its
   resolved route.
4. UDP transport rejects outbound and inbound datagrams larger than
   `underlay_mtu - 28`.
5. Before Wintun injection, the tunnel requires an exact, checksum-valid IPv4
   packet whose declared total length equals the decrypted buffer length and
   whose size does not exceed the configured overlay MTU.

The interactive `/status` command reports the active `Overlay MTU`. Its
`MTU Drops` line includes these counters:

- `outbound`: inner packets too large for their resolved routes.
- `inbound`: decrypted inner packets larger than the overlay MTU.
- `invalid`: malformed, truncated, or trailing-byte inner IPv4 packets.
- `wire-send` and `wire-receive`: UDP datagrams outside the transport budget.

It also reports `Queue Drops` split between data and reserved control traffic,
plus `Relay Usage` with admitted packet/byte totals and per-peer, global, and
peer-capacity quota drops. Relay counters reset when the tunnel starts; queue
counters reset whenever its transport is bound.

The first drop in each tunnel category, and then every hundredth drop, is also
logged.

File transfers negotiate their authenticated chunk size from the active
overlay MTU. Chunk data is limited to
`min(overlay_mtu, session_plaintext_limit) - file_chunk_header`, so the
complete encrypted file frame remains inside both the configured path budget
and the 4 KiB session-plaintext ceiling.

### Operational requirements

Set `underlay_mtu` no higher than the smallest physical IPv4 path MTU that any
configured Aegis route may traverse. Because Aegis does not discover path MTU,
an overly large value can still cause outer IP fragmentation or loss below the
Aegis layer.

Use a common conservative `underlay_mtu` and `max_relay_depth` across a mesh.
Nodes may technically use different values, but a sender with a larger overlay
MTU can produce an inner packet that a more conservative receiver rejects.

If the resulting overlay MTU is too restrictive, reducing relay depth increases
the available payload budget. Overlay fragmentation must be specified and
implemented as a separate bounded protocol before packets larger than this
contract can be carried safely.

---

## Testing

```cmd
REM Run all CTest unit tests
cmake --build build --target check

REM Run individual test binaries directly
build\bin\Release\test_packet.exe
build\bin\Release\test_session.exe
build\bin\Release\test_relay.exe
build\bin\Release\test_peer_table.exe
build\bin\Release\test_routing.exe
build\bin\Release\test_config.exe
build\bin\Release\test_invite.exe
build\bin\Release\test_stun.exe
REM ... etc.
```

Unit test coverage:

| Test Binary | What It Covers |
|:------------|:---------------|
| `test_packet` | IP parsing, exact decrypted-packet validation, encrypted frames, layer typing, and the full route-depth MTU budget matrix |
| `test_wire` | Bounded network-byte-order readers/writers and atomic failure behavior |
| `test_file_transfer` | Canonical file/ACK/cancel framing, MTU sizing, sender isolation, selective ACK/retransmission and resume behavior, timeout/quota boundaries, SHA-256 verification, atomic `.part` publication, and malformed-frame rejection |
| `test_handshake_v2` | Canonical Noise IK INIT/RESP envelope framing and malformed-frame rejection |
| `test_noise_dependency` | Pinned Noise-C suite availability and unsupported-algorithm confinement |
| `test_noise_ik` | Noise vectors, transcript/split verification, malformed-message rejection, and failed-state destruction |
| `test_transport` | Winsock loopback, bounded priority send queues, control-capacity reservation, queue-drop accounting, MTU-derived datagram limits, socket lifecycle, bounded handshake admission, and stateless retry cookies |
| `test_crypto` | X25519 keygen, shared secret derivation, determinism |
| `test_random` | Checked random-source injection and CSPRNG generation |
| `test_primitives` | SHA-256/BLAKE2s transcript hashes, HMAC/HKDF vectors, constant-time comparison |
| `test_secret` | Cleansing secret storage copy, move, overwrite, and destruction behavior |
| `test_aead` | ChaCha20-Poly1305 RFC 8439 test vectors, tamper rejection |
| `test_identity` | Legacy NodeID hashing, separate Ed25519/X25519 keys, signed key-binding verification/tamper rejection, and NetworkID equality |
| `test_tunnel` | Nonce counter arithmetic, wire format round-trip, AEAD integration |
| `test_session` | Authenticated Noise IK integration, concurrent lifecycle/snapshot safety, bounded session state, pending-state expiry, INIT replay caching, simultaneous-init convergence, transport replay windows, and rekey grace |
| `test_peer` | Multi-peer table — concurrent lifecycle/snapshot safety, states, endpoints, session lookup, health tracking |
| `test_routing` | Prefix → next-hop → peer resolution, retained and bounded candidates, exact learned-lease expiry, direct-to-relay circuit fallback and hold-down recovery, direct-route preservation, canonical prefixes, route refresh, loop rejection, and tie-breaking |
| `test_peer_table` | TYPE_PEER_TABLE v3 encoding/merge, sequence/lease/metric validation, stale-sequence rejection, alternate-advertiser retention, IP-stripping, bounded delta batching, and jitter scheduling |
| `test_relay` | `build_onion` / `peel_onion`, path-probe codec and bounded challenge tracking, per-hop decryption, wire-budget agreement, and deterministic relay quota enforcement |
| `test_discovery` | LAN presence broadcast format, NetworkID extraction, endpoint parsing |
| `test_config` | YAML parsing, strict validation, unknown-key rejection, malformed value errors |
| `test_invite` | AEGIS1 invite code encoding, decoding, validation, round-trip |
| `test_stun` | RFC 5389 request/response validation, XOR-MAPPED-ADDRESS parsing, and loopback proof that discovery uses the bound mesh UDP port |
| `test_endpoint_candidate` | Canonical bounded candidate framing, all candidate types, authenticated punch framing, transaction/peer/source matching, timeout boundaries, and malformed length/version/type handling |
| `test_nat_simulation` | Deterministic endpoint-independent and symmetric NAT mappings, direct punch reachability, failed-punch retention, relay-route fallback, and onion delivery through a relay circuit |
| `test_cli` | CLI parsing/dispatch, versioned identity persistence, stable signer round-trip, legacy-key migration, and fail-closed corrupt-credential handling |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Run the full test suite (`cmake --build build --target check`)
4. Submit a pull request against `master`

The CI build pipeline must pass before merge.

---

<div align="center">

**Built by [Vishal Shetagar](https://github.com/vishalss1)**

*C++20 · OpenSSL EVP · Wintun · Winsock · X25519 · ChaCha20-Poly1305 · BLAKE2b · CMake*

[![GitHub](https://img.shields.io/badge/GitHub-vishalss1-181717?style=flat&logo=github)](https://github.com/vishalss1)

</div>
