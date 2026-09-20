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

[Security Status](#security-status) · [What Is Aegis](#what-is-aegis) · [Engineering Decisions](#engineering-decisions) · [Architecture](#architecture) · [Features](#features) · [Onion Security Model](#onion-security-model) · [CI/CD](#cicd-pipeline) · [Tech Stack](#tech-stack) · [Quick Start](#quick-start) · [Usage](#usage) · [Config Format](#configuration-file) · [Testing](#testing)

---

## Security Status

> [!WARNING]
> Aegis is an experimental prototype and is not ready to protect sensitive or
> production traffic. The current handshake does not authenticate static peer
> identities. Gossip now enforces the NodeID/public-key binding at its merge
> boundary, but route ownership, MTU, resource-exhaustion, and reliability
> protections remain incomplete. See
> [SECURITY.md](SECURITY.md) for the current guarantees and known limitations.

---

## What Is Aegis

Most VPNs stop at "two endpoints, one encrypted tunnel." Aegis explores a decentralized mesh in which nodes are addressed by public-key-derived identifiers. The current handshake does not yet authenticate those identifiers. Traffic between non-adjacent nodes can be onion-wrapped, but relays still observe the logical source NodeID, adjacent hops, packet sizes, and timing.

Built as a Windows-native CLI binary that creates a Wintun virtual adapter, Aegis routes overlay traffic through a fully layered stack:

```
Identity  →  Session (X25519 handshake)  →  Routing (prefix → next-hop → peer)
→  Onion Wrapping (ChaCha20-Poly1305 layers)  →  UDP (Winsock)  →  Internet
```

A VPN point-to-point tunnel is only the first application of this overlay. The mesh is the product.

---

## Engineering Decisions

A few design choices that shaped how Aegis works.

**NodeID, not IP, is the intended identity.** Every node derives a 32-byte `NodeID` as `BLAKE2b(PublicKey)`. Peer-table merge rejects a public key that does not hash to its advertised NodeID, and established non-empty peer keys are immutable through `upsert`. The session handshake still does not prove possession of the corresponding static private key.

**Onion routing is a core requirement, not a stretch goal.** Each hop decrypts one `ChaCha20-Poly1305` layer keyed by `SHA256("aegis-onion-v1" ‖ X25519(our_priv, source_pub))`. The current framing exposes the source NodeID to every relay and does not pad length or timing, so it should not yet be treated as a complete anonymity system.

**A mesh with no fixed entry point.** Nodes are provisioned with a list of bootstrap candidates via out-of-band config. Joining follows an availability-based policy — each candidate gets its own background connect loop with exponential backoff. The node comes up and starts routing immediately even if zero peers are reachable. Whichever candidate becomes available first is used; no node is a server.

**Peer table gossip with IP-stripping.** Once a session exists, every node fans out its full peer table so the mesh converges on all members. Endpoints are omitted from gossip, which limits physical-address propagation. Gossip validates advertised NodeID/public-key bindings, but does not authenticate prefix ownership, path origin, or the advertising member's honesty.

**NetworkID gates sessions, not discovery.** A mismatched NetworkID is rejected before a session is created. NetworkID is currently sent in cleartext and must be treated as a mesh selector or bearer value, not peer authentication. LAN presence broadcasts are unauthenticated and network-agnostic.

**Layered packet processing.** The Packet Engine separates IP parsing, session framing, relay wrapping, and UDP transport. Some current module boundaries still exchange raw byte buffers and parse fields with manual offsets; bounded typed codecs are planned before the handshake rewrite.

**Rekeying without a new packet type.** Session rekeying is a fresh X25519 handshake with a new session ID — identical to initial connection. The prior session is retired into a 10-second grace window so in-flight packets under the old key still decrypt cleanly. The lower-NodeID peer drives rekeying every 120 seconds. Replay windows and sequence numbers restart per session ID.

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
         │  │  Direct routes + Relay routes         │   │
         │  │  Loop detection · mutex-serialised    │   │
         │  └───────────────┬───────────────────────┘   │
         │                  │                           │
         │  ┌───────────────┴───────────────────────┐   │
         │  │          Session Manager              │   │
         │  │  X25519 handshake · rekeying          │   │
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
         │  │  Datagram I/O · background rx thread │   │
         │  └───────────────┬───────────────────────┘   │
         └───────────────────┼──────────────────────────┘
                             │ Encrypted UDP datagrams
                   ┌─────────┴──────────┐
                   │    UDP / Winsock   │
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
| UDP (TYPE_HANDSHAKE_INIT/RESP) | Initiator → Responder | X25519 key agreement |
| UDP (TYPE_KEEPALIVE) | Peer ↔ Peer | Empty encrypted frame — liveness + NAT keepalive |
| UDP (TYPE_PEER_TABLE) | Peer ↔ Peer | Gossip — NodeID + pubkey + prefixes (no IPs) |
| UDP (TYPE_DISCOVERY) | LAN broadcast | Presence — NodeID + NetworkID + endpoint (pre-session) |

---

## Features

| Feature | What It Does |
|:--------|:-------------|
| **NodeID Addressing** | Peers are addressed as `NodeID = BLAKE2b(PublicKey)`. Received gossip enforces that binding; the current handshake does not authenticate it. |
| **X25519 + ChaCha20-Poly1305** | Ephemeral X25519 derives session keys and ChaCha20-Poly1305 authenticates data frames. The handshake itself does not authenticate static identities or provide transcript key confirmation. |
| **Multi-hop Onion Routing** | Each hop decrypts one layer and learns the next hop. Relays also receive the source NodeID, and unpadded packet size and timing remain visible. |
| **Peer Table Gossip** | Full mesh convergence without a coordinator. Every new session triggers a fan-out of the peer table; a periodic 3-second gossip loop ensures far-end peers propagate across multi-hop chains. |
| **Identity-Hiding Gossip** | Peer tables carry NodeID + public key + IP prefix routes. Physical endpoints are never transmitted in gossip — non-adjacent nodes cannot learn each other's real IP. |
| **NetworkID Mesh Segmentation** | NetworkID mismatches are rejected before session creation. This separates accidental cross-mesh traffic but is not static peer authentication. |
| **Join-Any-Available Bootstrap** | No fixed entry point, no dedicated server. Each configured candidate gets its own background connect loop with exponential backoff (1s → 30s cap). The node routes immediately; sessions form as peers become reachable. |
| **Session Keep-Alive & Dead Detection** | Keep-alives every 25s. Dead timeout at 180s removes the session and all routes. Configured peers are re-joined automatically on reconnect, routes reinstalled, peer table re-announced. |
| **Transparent Rekeying** | Fresh X25519 handshake every 120s driven by the lower-NodeID peer. Prior session retired to a 10s grace window — in-flight packets decrypt cleanly. Replay windows and sequence numbers reset per session ID. |
| **Endpoint Self-Healing** | LAN presences provide endpoint hints for configured peers. Broadcasts are unauthenticated, so these hints can be spoofed and must not yet be considered validated endpoints. |
| **YAML Config Mode** | `--config <file>` — strict YAML subset parser. Validates all fields, rejects unknown keys. Auto-elevates via UAC (`ShellExecuteW "runas"`) when launched without Administrator rights. |
| **Replay Protection** | Per-session sliding window of 2048 sequence numbers. Out-of-window and duplicate sequence numbers are silently discarded. |
| **Layered Packet Processing** | IP parsing, session framing, relay wrapping, and UDP transport are separate modules. Raw byte-buffer interfaces and manual offsets still exist and require bounded codec replacements. |

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

Keys are generated once at node startup (static X25519 keypair). Onion layer keys are static per `(source, hop)` pair and are not forward-secret. Adjacent session keys use fresh ephemeral DH, but the current handshake does not authenticate those ephemeral keys to the static peer identity. See [SECURITY.md](SECURITY.md) before relying on these properties.

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
| **Testing** | CTest unit suite — 13 independent test binaries |

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
│       ├── transport/          # Winsock UDP socket send/receive
│       └── tunnel/             # Integrated data path — tx/rx loops, maintenance
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
│   ├── transport/transport.cpp
│   └── tunnel/tunnel.cpp       # tx_loop, rx_loop, maintenance loop
├── tests/                      # CTest unit test suite — 15 binaries
│   ├── test_packet.cpp
│   ├── test_transport.cpp
│   ├── test_crypto.cpp
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
│   └── test_stun.cpp
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
  # Optional STUN server for WAN public IP:port discovery (RFC 5389)
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
| `test_packet` | IP packet parsing, encrypted frame construction, layer typing |
| `test_transport` | Winsock loopback — UDP send/receive, socket lifecycle |
| `test_crypto` | X25519 keygen, shared secret derivation, determinism |
| `test_aead` | ChaCha20-Poly1305 RFC 8439 test vectors, tamper rejection |
| `test_identity` | NodeID hashing, NetworkID equality, keypair round-trip |
| `test_tunnel` | Nonce counter arithmetic, wire format round-trip, AEAD integration |
| `test_session` | Handshake initiation/response, key derivation, replay window, rekey grace |
| `test_peer` | Multi-peer table — states, endpoints, session lookup, health tracking |
| `test_routing` | Prefix → next-hop → peer resolution, Direct/Relay/Unknown types, loop rejection, tie-breaking |
| `test_peer_table` | TYPE_PEER_TABLE wire encoding/decoding, gossip merge, IP-stripping |
| `test_relay` | `build_onion` / `peel_onion` — layer construction, per-hop decryption, innermost injection |
| `test_discovery` | LAN presence broadcast format, NetworkID extraction, endpoint parsing |
| `test_config` | YAML parsing, strict validation, unknown-key rejection, malformed value errors |
| `test_invite` | AEGIS1 invite code encoding, decoding, validation, round-trip |
| `test_stun` | RFC 5389 STUN Binding Request formatting, XOR-MAPPED-ADDRESS parsing |

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
