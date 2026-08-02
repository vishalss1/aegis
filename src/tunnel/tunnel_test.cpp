#include "aegis/tunnel/tunnel_test.hpp"
#include "aegis/tunnel/tunnel.hpp"
#include "aegis/peer/peer.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>

namespace {

const uint32_t IP_A = htonl((10u << 24) | (10u << 16) | (0u << 8) | 1u);  // 10.10.0.1
const uint32_t IP_B = htonl((10u << 24) | (20u << 16) | (0u << 8) | 1u);  // 10.20.0.1
const uint32_t IP_C = htonl((10u << 24) | (30u << 16) | (0u << 8) | 1u);  // 10.30.0.1
const uint32_t IP_D = htonl((10u << 24) | (40u << 16) | (0u << 8) | 1u);  // 10.40.0.1
// Ports sit below Windows' ephemeral/excluded range (49k+). The original
// 51820-51822 land inside the dynamic "Administered port exclusions" band
// (Windows reserves ranges there on the fly), which intermittently failed
// bind with WSAEACCES.
const uint16_t PORT_A = 45120;
const uint16_t PORT_B = 45121;
const uint16_t PORT_C = 45122;
const uint16_t PORT_D = 45123;

// A phantom bootstrap candidate: this endpoint never listens. C is configured
// with it to prove that an unreachable candidate does not block joining the
// mesh via the candidates that ARE reachable (availability-based join).
const uint16_t PORT_X = 45999;
const char* PHANTOM_CIDR = "10.90.0.0/24";

// Routing prefixes use the same big-endian-value representation as
// IPPacket::dest_ip, so `allow(10,20,0,0,24)` matches 10.20.0.x packets.
AllowedIP allow(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t len) {
    return { (static_cast<uint32_t>(a) << 24) |
             (static_cast<uint32_t>(b) << 16) |
             (static_cast<uint32_t>(c) << 8)  |
             static_cast<uint32_t>(d), len };
}

// The /32 host routes below are what force the test's UDP packets OUT of the
// adapters and through the encrypted tunnels. Without them, Windows delivers
// to a local address over its implicit loopback host route and the packet
// never touches the tunnel.
void add_route(const char* dst, const char* mask, const char* gw) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "route delete %s mask %s %s >nul 2>&1", dst, mask, gw);
    std::system(cmd);
    snprintf(cmd, sizeof(cmd), "route add %s mask %s %s metric 6", dst, mask, gw);
    int rc = std::system(cmd);
    if (rc != 0)
        fprintf(stderr, "[tunnel-test] warning: route add %s/%s via %s returned %d\n",
                dst, mask, gw, rc);
}

void delete_route(const char* dst, const char* mask, const char* gw) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "route delete %s mask %s %s >nul 2>&1", dst, mask, gw);
    std::system(cmd);
}

// Same as add_route but pins the route to a specific interface index. On a
// single host with several Wintun adapters, gateway-based interface resolution
// can cross-wire reciprocal /32 routes (an explicit route to the gateway
// shadows the on-link route), so the relay test binds its routes explicitly.
void add_route_if(const char* dst, const char* mask, const char* gw, uint32_t ifidx) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "route delete %s mask %s %s >nul 2>&1", dst, mask, gw);
    std::system(cmd);
    snprintf(cmd, sizeof(cmd), "route add %s mask %s %s IF %lu metric 6",
            dst, mask, gw, (unsigned long)ifidx);
    int rc = std::system(cmd);
    if (rc != 0)
        fprintf(stderr, "[tunnel-test] warning: route add %s/%s via %s IF %lu returned %d\n",
                dst, mask, gw, (unsigned long)ifidx, rc);
}

// Poll the peer table until the session with `node_id` is established. start()
// is non-blocking (mesh bootstrap), so sessions appear in the background.
bool wait_for_established(const PeerManager& pm, const NodeId& node_id, int timeout_sec) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(timeout_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        const Peer* p = pm.get_peer(node_id);
        if (p && p->state == PeerState::Established)
            return true;
        Sleep(100);
    }
    return false;
}

// One UDP round trip between two adapter IPs. Proves tunnel `sender_ip` routes
// traffic for `listener_ip` to the correct peer and back.
bool udp_round_trip(uint32_t sender_ip, uint32_t listener_ip, const char* tag) {
    SOCKET listener = socket(AF_INET, SOCK_DGRAM, 0);
    if (listener == INVALID_SOCKET) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: socket(listener): %d\n", tag, WSAGetLastError());
        return false;
    }
    struct sockaddr_in laddr = {};
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = listener_ip;
    laddr.sin_port = 0;
    if (bind(listener, (struct sockaddr*)&laddr, sizeof(laddr)) != 0) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: bind listener: %d "
                "(close any stale test sockets holding the port first)\n",
                tag, WSAGetLastError());
        closesocket(listener);
        return false;
    }
    int llen = sizeof(laddr);
    getsockname(listener, (struct sockaddr*)&laddr, &llen);
    uint16_t listener_port = ntohs(laddr.sin_port);

    SOCKET sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender == INVALID_SOCKET) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: socket(sender): %d\n", tag, WSAGetLastError());
        closesocket(listener);
        return false;
    }
    struct sockaddr_in saddr = {};
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = sender_ip;
    saddr.sin_port = 0;
    if (bind(sender, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: bind sender: %d\n", tag, WSAGetLastError());
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    int slen = sizeof(saddr);
    getsockname(sender, (struct sockaddr*)&saddr, &slen);
    uint16_t sender_port = ntohs(saddr.sin_port);

    DWORD timeout = 5000;
    setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sender, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    char lip[32], sip[32];
    snprintf(lip, sizeof(lip), "%u.%u.%u.%u", (ntohl(listener_ip) >> 24) & 0xFF,
             (ntohl(listener_ip) >> 16) & 0xFF, (ntohl(listener_ip) >> 8) & 0xFF,
             ntohl(listener_ip) & 0xFF);
    snprintf(sip, sizeof(sip), "%u.%u.%u.%u", (ntohl(sender_ip) >> 24) & 0xFF,
             (ntohl(sender_ip) >> 16) & 0xFF, (ntohl(sender_ip) >> 8) & 0xFF,
             ntohl(sender_ip) & 0xFF);

    // --- forward: sender -> listener, must cross the encrypted tunnel -------
    const char* hello = "hello-tunnel";
    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = listener_ip;
    dst.sin_port = htons(listener_port);
    if (sendto(sender, hello, (int)std::strlen(hello), 0,
               (struct sockaddr*)&dst, sizeof(dst)) == SOCKET_ERROR) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: forward sendto: %d\n", tag, WSAGetLastError());
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    printf("[tunnel-test] %s: %s -> %s:%u\n", tag, sip, lip, listener_port);

    char buf[64] = {};
    struct sockaddr_in from = {};
    int fromlen = sizeof(from);
    int r = recvfrom(listener, buf, sizeof(buf), 0,
                     (struct sockaddr*)&from, &fromlen);
    if (r == (int)std::strlen(hello) && std::memcmp(buf, hello, std::strlen(hello)) == 0) {
        printf("[tunnel-test] %s: forward recv on %s: \"%.*s\" via tunnel\n",
               tag, lip, r, buf);
    } else {
        fprintf(stderr, "[tunnel-test] %s: FAIL: forward recv: got %d bytes (err %d), expected \"%s\"\n",
                tag, r, WSAGetLastError(), hello);
        closesocket(listener);
        closesocket(sender);
        return false;
    }

    // --- return: listener replies to the sender -----------------------------
    const char* pong = "pong";
    if (sendto(listener, pong, (int)std::strlen(pong), 0,
               (struct sockaddr*)&from, fromlen) == SOCKET_ERROR) {
        fprintf(stderr, "[tunnel-test] %s: FAIL: return sendto: %d\n", tag, WSAGetLastError());
        std::system("route print 10.10.0.1");
        std::system("route print 10.40.0.1");
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    printf("[tunnel-test] %s: return %s -> %s:%u\n", tag, lip, sip, sender_port);

    r = recvfrom(sender, buf, sizeof(buf), 0,
                 (struct sockaddr*)&from, &fromlen);
    if (r == (int)std::strlen(pong) && std::memcmp(buf, pong, std::strlen(pong)) == 0) {
        printf("[tunnel-test] %s: return recv on %s: \"%.*s\" via tunnel\n",
               tag, sip, r, buf);
    } else {
        fprintf(stderr, "[tunnel-test] %s: FAIL: return recv: got %d bytes (err %d), expected \"%s\"\n",
                tag, r, WSAGetLastError(), pong);
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    closesocket(listener);
    closesocket(sender);
    return true;
}

} // namespace

int run_tunnel_test() {
    printf("[tunnel-test] starting\n");
    printf("[tunnel-test] mesh bootstrap: A (10.10.0.1:%u), B (10.20.0.1:%u), C (10.30.0.1:%u)\n",
           PORT_A, PORT_B, PORT_C);
    printf("[tunnel-test] staged join (availability-based, not fixed topology):\n");
    printf("[tunnel-test]   1. A starts alone (B and C down) -> A stays up, retries in background\n");
    printf("[tunnel-test]   2. B starts -> A and B reconnect via background retry\n");
    printf("[tunnel-test]   3. C starts with A, B, AND a phantom peer (%s) that never listens\n",
           PHANTOM_CIDR);
    printf("[tunnel-test]      C must still join A and B despite the unreachable candidate\n");
    printf("[tunnel-test] /32 host routes suppress local loopback delivery so UDP must transit the tunnels\n");
    printf("[tunnel-test] note: UDP only - ICMP cannot be verified on a single host (Windows drops looped-back echo replies)\n");

    // Fixed identities so each node can be pre-configured with the others'
    // NodeIDs and public keys (peer table propagation learns these later).
    NetworkId net{};
    net[0] = 0x01;
    Identity id_a = Identity::create(net);
    Identity id_b = Identity::create(net);
    Identity id_c = Identity::create(net);
    Identity id_x = Identity::create(net);  // phantom, never runs

    TunnelConfig cfg_a;
    cfg_a.identity = id_a;
    cfg_a.local_ip = IP_A;
    cfg_a.local_prefix = 24;
    cfg_a.listen_port = PORT_A;
    cfg_a.peers = {
        { id_b.node_id, id_b.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_B),
          { allow(10, 20, 0, 0, 24) } },
        { id_c.node_id, id_c.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_C),
          { allow(10, 30, 0, 0, 24) } },
    };

    TunnelConfig cfg_b;
    cfg_b.identity = id_b;
    cfg_b.local_ip = IP_B;
    cfg_b.local_prefix = 24;
    cfg_b.listen_port = PORT_B;
    cfg_b.peers = {
        { id_a.node_id, id_a.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_A),
          { allow(10, 10, 0, 0, 24) } },
        { id_c.node_id, id_c.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_C),
          { allow(10, 30, 0, 0, 24) } },
    };

    TunnelConfig cfg_c;
    cfg_c.identity = id_c;
    cfg_c.local_ip = IP_C;
    cfg_c.local_prefix = 24;
    cfg_c.listen_port = PORT_C;
    cfg_c.peers = {
        { id_a.node_id, id_a.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_A),
          { allow(10, 10, 0, 0, 24) } },
        { id_b.node_id, id_b.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_B),
          { allow(10, 20, 0, 0, 24) } },
        { id_x.node_id, id_x.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_X),
          { allow(10, 90, 0, 0, 24) } },
    };

    Tunnel tunnel_a;
    Tunnel tunnel_b;
    Tunnel tunnel_c;

    bool pass = true;

    // ---- phase 1: A alone, B and C down ------------------------------------
    printf("[tunnel-test] phase 1: starting A alone (peers B, C down)\n");
    if (!tunnel_a.start(cfg_a, "Aegis 10.10.0.1")) {
        fprintf(stderr, "[tunnel-test] FAIL: A failed to start\n");
        return 1;
    }
    printf("[tunnel-test] A is up with zero reachable peers (join-any policy)\n");
    Sleep(2000);  // give A's connect loops a chance to fail once on B and C

    // ---- phase 2: B starts, A reconnects via background retry ---------------
    printf("[tunnel-test] phase 2: starting B\n");
    if (!tunnel_b.start(cfg_b, "Aegis 10.20.0.1")) {
        fprintf(stderr, "[tunnel-test] FAIL: B failed to start\n");
        pass = false;
    }
    if (pass) {
        bool ab_ok = wait_for_established(tunnel_a.peers(), id_b.node_id, 40);
        ab_ok = wait_for_established(tunnel_b.peers(), id_a.node_id, 40) && ab_ok;
        if (ab_ok) {
            printf("[tunnel-test] A<->B established via background retry: OK\n");
        } else {
            fprintf(stderr, "[tunnel-test] FAIL: A<->B never established\n");
            pass = false;
        }
    }

    // ---- phase 3: C joins with a phantom candidate down ---------------------
    printf("[tunnel-test] phase 3: starting C (candidates A, B, phantom X)\n");
    if (pass && !tunnel_c.start(cfg_c, "Aegis 10.30.0.1")) {
        fprintf(stderr, "[tunnel-test] FAIL: C failed to start\n");
        pass = false;
    }
    if (pass) {
        bool c_ok = wait_for_established(tunnel_c.peers(), id_a.node_id, 40);
        c_ok = wait_for_established(tunnel_c.peers(), id_b.node_id, 40) && c_ok;
        c_ok = wait_for_established(tunnel_a.peers(), id_c.node_id, 40) && c_ok;
        c_ok = wait_for_established(tunnel_b.peers(), id_c.node_id, 40) && c_ok;
        if (c_ok) {
            printf("[tunnel-test] C joined A and B despite phantom X being down: OK\n");
        } else {
            fprintf(stderr, "[tunnel-test] FAIL: C did not join the mesh (phantom block?)\n");
            pass = false;
        }
    }

    if (!pass) {
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        return 1;
    }
    printf("[tunnel-test] full mesh established: A<->B, A<->C, B<->C\n");

    // Mesh-wide routes: traffic to another subnet leaves through the local
    // adapter; /32 entries keep Windows from short-circuiting over loopback.
    add_route("10.20.0.0", "255.255.255.0", "10.10.0.1");
    add_route("10.30.0.0", "255.255.255.0", "10.10.0.1");
    add_route("10.10.0.0", "255.255.255.0", "10.20.0.1");
    add_route("10.30.0.0", "255.255.255.0", "10.20.0.1");
    add_route("10.10.0.0", "255.255.255.0", "10.30.0.1");
    add_route("10.20.0.0", "255.255.255.0", "10.30.0.1");
    add_route("10.20.0.1", "255.255.255.255", "10.10.0.1");
    add_route("10.30.0.1", "255.255.255.255", "10.10.0.1");
    add_route("10.10.0.1", "255.255.255.255", "10.20.0.1");
    add_route("10.30.0.1", "255.255.255.255", "10.20.0.1");
    add_route("10.10.0.1", "255.255.255.255", "10.30.0.1");
    add_route("10.20.0.1", "255.255.255.255", "10.30.0.1");

    pass = udp_round_trip(IP_A, IP_B, "A->B") && pass;
    pass = udp_round_trip(IP_A, IP_C, "A->C") && pass;
    pass = udp_round_trip(IP_B, IP_C, "B->C") && pass;

    delete_route("10.20.0.1", "255.255.255.255", "10.10.0.1");
    delete_route("10.30.0.1", "255.255.255.255", "10.10.0.1");
    delete_route("10.10.0.1", "255.255.255.255", "10.20.0.1");
    delete_route("10.30.0.1", "255.255.255.255", "10.20.0.1");
    delete_route("10.10.0.1", "255.255.255.255", "10.30.0.1");
    delete_route("10.20.0.1", "255.255.255.255", "10.30.0.1");
    delete_route("10.20.0.0", "255.255.255.0", "10.10.0.1");
    delete_route("10.30.0.0", "255.255.255.0", "10.10.0.1");
    delete_route("10.10.0.0", "255.255.255.0", "10.20.0.1");
    delete_route("10.30.0.0", "255.255.255.0", "10.20.0.1");
    delete_route("10.10.0.0", "255.255.255.0", "10.30.0.1");
    delete_route("10.20.0.0", "255.255.255.0", "10.30.0.1");

    tunnel_a.stop();
    tunnel_b.stop();
    tunnel_c.stop();

    if (pass) {
        printf("[tunnel-test] *** ALL PASS ***\n");
        return 0;
    }
    fprintf(stderr, "[tunnel-test] *** FAIL ***\n");
    return 1;
}

// Step 12/13: peer table propagation + relayed data. A-B-C-D chain where every
// node is configured with ONLY its direct neighbors. Full-mesh knowledge must
// emerge from gossip alone — no node is ever told about a non-adjacent peer —
// and then A<->D traffic must actually transit the chain onion-wrapped.
int run_gossip_test() {
    printf("[gossip-test] starting\n");
    printf("[gossip-test] chain A-B-C-D, each node configured with only its direct neighbors\n");
    printf("[gossip-test] A (10.10.0.1:%u) -- B (10.20.0.1:%u) -- C (10.30.0.1:%u) -- D (10.40.0.1:%u)\n",
           PORT_A, PORT_B, PORT_C, PORT_D);
    printf("[gossip-test] convergence = every node's peer table reaches size 3 (all other nodes)\n");
    printf("[gossip-test] learned peers must be untrusted and endpoint-less (real IPs never propagate)\n");
    printf("[gossip-test] then: relayed A<->D UDP round-trip through B and C (step 13)\n");

    NetworkId net{};
    net[0] = 0x01;
    Identity id_a = Identity::create(net);
    Identity id_b = Identity::create(net);
    Identity id_c = Identity::create(net);
    Identity id_d = Identity::create(net);

    TunnelConfig cfg_a;
    cfg_a.identity = id_a;
    cfg_a.local_ip = IP_A;
    cfg_a.local_prefix = 24;
    cfg_a.listen_port = PORT_A;
    cfg_a.peers = {
        { id_b.node_id, id_b.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_B),
          { allow(10, 20, 0, 0, 24) } },
    };

    TunnelConfig cfg_b;
    cfg_b.identity = id_b;
    cfg_b.local_ip = IP_B;
    cfg_b.local_prefix = 24;
    cfg_b.listen_port = PORT_B;
    cfg_b.peers = {
        { id_a.node_id, id_a.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_A),
          { allow(10, 10, 0, 0, 24) } },
        { id_c.node_id, id_c.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_C),
          { allow(10, 30, 0, 0, 24) } },
    };

    TunnelConfig cfg_c;
    cfg_c.identity = id_c;
    cfg_c.local_ip = IP_C;
    cfg_c.local_prefix = 24;
    cfg_c.listen_port = PORT_C;
    cfg_c.peers = {
        { id_b.node_id, id_b.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_B),
          { allow(10, 20, 0, 0, 24) } },
        { id_d.node_id, id_d.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_D),
          { allow(10, 40, 0, 0, 24) } },
    };

    TunnelConfig cfg_d;
    cfg_d.identity = id_d;
    cfg_d.local_ip = IP_D;
    cfg_d.local_prefix = 24;
    cfg_d.listen_port = PORT_D;
    cfg_d.peers = {
        { id_c.node_id, id_c.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_C),
          { allow(10, 30, 0, 0, 24) } },
    };

    Tunnel tunnel_a;
    Tunnel tunnel_b;
    Tunnel tunnel_c;
    Tunnel tunnel_d;

    if (!tunnel_a.start(cfg_a, "Aegis 10.10.0.1") ||
        !tunnel_b.start(cfg_b, "Aegis 10.20.0.1") ||
        !tunnel_c.start(cfg_c, "Aegis 10.30.0.1") ||
        !tunnel_d.start(cfg_d, "Aegis 10.40.0.1")) {
        fprintf(stderr, "[gossip-test] FAIL: a tunnel failed to start\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] all four nodes up; waiting for sessions + gossip convergence\n");

    // Every node must learn the full mesh: peer table size 3 (all others).
    auto converged = [&]() {
        return tunnel_a.peers().size() == 3 &&
               tunnel_b.peers().size() == 3 &&
               tunnel_c.peers().size() == 3 &&
               tunnel_d.peers().size() == 3;
    };
    bool ok = false;
    for (int i = 0; i < 80 && !ok; i++) {   // up to 80s (5x gossip interval + slack)
        if (converged()) { ok = true; break; }
        Sleep(1000);
    }

    printf("[gossip-test] peer tables:\n");
    const Tunnel* nodes[4] = { &tunnel_a, &tunnel_b, &tunnel_c, &tunnel_d };
    const char* names[4] = { "A", "B", "C", "D" };
    for (int n = 0; n < 4; n++) {
        printf("[gossip-test]   %s (%zu peer(s)):", names[n], nodes[n]->peers().size());
        for (const auto* p : nodes[n]->peers().all_peers()) {
            printf(" %c%c%c%c", (p->node_id == id_a.node_id ? 'A' :
                                 p->node_id == id_b.node_id ? 'B' :
                                 p->node_id == id_c.node_id ? 'C' :
                                 p->node_id == id_d.node_id ? 'D' : '?'),
                   p->trusted ? 't' : 'l', p->endpoint ? 'e' : '-', ' ');
        }
        printf("\n");
    }

    if (!ok) {
        fprintf(stderr, "[gossip-test] FAIL: peer tables did not converge to size 3\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] convergence: all nodes know the full mesh: OK\n");

    // Cross-checks on specific knowledge + route installation.
    bool pass = true;
    const auto& pa = tunnel_a.peers();
    const auto& pd = tunnel_d.peers();
    const auto& pb = tunnel_b.peers();

    auto has_peer = [](const PeerManager& pm, const NodeId& id) {
        const Peer* p = pm.get_peer(id);
        return p != nullptr;
    };

    // A must know C and D; D must know A and B; B must know D.
    pass = has_peer(pa, id_c.node_id) && pass;
    pass = has_peer(pa, id_d.node_id) && pass;
    pass = has_peer(pd, id_a.node_id) && pass;
    pass = has_peer(pd, id_b.node_id) && pass;
    pass = has_peer(pb, id_d.node_id) && pass;
    if (!pass) {
        fprintf(stderr, "[gossip-test] FAIL: cross-mesh knowledge incomplete\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] A knows C,D / D knows A,B / B knows D: OK\n");

    // Learned peers are untrusted and carry no endpoint (identity hiding).
    auto untrusted_no_endpoint = [](const PeerManager& pm, const NodeId& id) {
        const Peer* p = pm.get_peer(id);
        return p && !p->trusted && !p->endpoint.has_value();
    };
    pass = untrusted_no_endpoint(pa, id_d.node_id) && pass;   // A learned D via B
    pass = untrusted_no_endpoint(pd, id_a.node_id) && pass;   // D learned A via C
    if (!pass) {
        fprintf(stderr, "[gossip-test] FAIL: learned peer must be untrusted with no endpoint\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] learned peers are untrusted, endpoint-less: OK\n");

    // Relay routes: A -> 10.40.0.0/24 next-hop B dest D via [B, C, D];
    // D -> 10.10.0.0/24 next-hop C dest A via [C, B, A].
    auto check_relay_route = [](const RoutingEngine& re, uint32_t prefix, uint8_t plen,
                                const NodeId& next_hop, const NodeId& dest,
                                const std::vector<NodeId>& path) {
        for (const auto& r : re.routes())
            if (r.prefix == prefix && r.prefix_length == plen &&
                r.next_hop == next_hop && r.destination == dest &&
                r.type == NextHopType::Relay && r.path == path)
                return true;
        return false;
    };
    pass = check_relay_route(tunnel_a.routing(), allow(10, 40, 0, 0, 24).prefix, 24,
                             id_b.node_id, id_d.node_id,
                             { id_b.node_id, id_c.node_id, id_d.node_id }) && pass;
    pass = check_relay_route(tunnel_d.routing(), allow(10, 10, 0, 0, 24).prefix, 24,
                             id_c.node_id, id_a.node_id,
                             { id_c.node_id, id_b.node_id, id_a.node_id }) && pass;
    if (!pass) {
        fprintf(stderr, "[gossip-test] FAIL: relay routes not installed with full hop paths\n");
        for (int n = 0; n < 4; n++) {
            fprintf(stderr, "[gossip-test]   %s routes:\n", names[n]);
            for (const auto& r : nodes[n]->routing().routes())
                fprintf(stderr, "[gossip-test]     %08x/%u type=%d next=%02x dest=%02x path=",
                        r.prefix, r.prefix_length, (int)r.type,
                        r.next_hop[0], r.destination[0]);
            fprintf(stderr, "[gossip-test]   %s routes end\n", names[n]);
        }
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] relay routes installed with full hop paths via direct neighbor: OK\n");

    // Step 13: an actual relayed UDP round-trip. A and D are NOT adjacent —
    // every packet must be onion-wrapped, bounced through B and C (2 relay
    // hops), and only unwrapped by the far end. /32 routes force the packet
    // off the local adapters and into the tunnels.
    printf("[gossip-test] relay round-trip A<->D through B and C (2 relay hops each way)\n");
    // Routes are bound to the owning adapter's interface index so the /32 host
    // routes force the packet off the local adapters and through the tunnels.
    add_route_if("10.40.0.0", "255.255.255.0", "10.10.0.1", tunnel_a.interface_index());
    add_route_if("10.40.0.1", "255.255.255.255", "10.10.0.1", tunnel_a.interface_index());
    add_route_if("10.10.0.0", "255.255.255.0", "10.40.0.1", tunnel_d.interface_index());
    add_route_if("10.10.0.1", "255.255.255.255", "10.40.0.1", tunnel_d.interface_index());

    pass = udp_round_trip(IP_A, IP_D, "A->D relay via B,C") && pass;

    delete_route("10.40.0.0", "255.255.255.0", "10.10.0.1");
    delete_route("10.40.0.1", "255.255.255.255", "10.10.0.1");
    delete_route("10.10.0.0", "255.255.255.0", "10.40.0.1");
    delete_route("10.10.0.1", "255.255.255.255", "10.40.0.1");

    if (!pass) {
        fprintf(stderr, "[gossip-test] FAIL: relayed A<->D round-trip\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        tunnel_d.stop();
        return 1;
    }
    printf("[gossip-test] relayed A<->D round-trip through B and C: OK\n");

    tunnel_a.stop();
    tunnel_b.stop();
    tunnel_c.stop();
    tunnel_d.stop();

    if (pass) {
        printf("[gossip-test] *** ALL PASS ***\n");
        return 0;
    }
    fprintf(stderr, "[gossip-test] *** FAIL ***\n");
    return 1;
}

// Step 14: NetworkID gating — multi-mesh segmentation on a shared LAN.
// net1 = {A, B} on 10.10/10.20, net2 = {C} on 10.30. All three nodes live on
// the same host and broadcast presence on the shared discovery port. They must
// SEE each other (presence is deliberately network-agnostic) but a session
// across networks must never form — C is even configured as a bootstrap
// candidate for A, and A's handshake with C must be refused at the NetworkID
// gate. A<->B must keep working normally.
int run_segmentation_test() {
    printf("[segmentation-test] starting\n");
    printf("[segmentation-test] net1 = {A 10.10.0.1:%u, B 10.20.0.1:%u}, net2 = {C 10.30.0.1:%u}\n",
           PORT_A, PORT_B, PORT_C);
    printf("[segmentation-test] same host, shared discovery port %u\n", DISCOVERY_PORT);
    printf("[segmentation-test] expected: presence visible across networks, sessions never\n");
    printf("[segmentation-test] A is configured with C as a bootstrap candidate — the join must be refused\n");

    NetworkId net1{};
    net1[0] = 0x01;
    NetworkId net2{};
    net2[0] = 0x02;

    Identity id_a = Identity::create(net1);
    Identity id_b = Identity::create(net1);
    Identity id_c = Identity::create(net2);

    TunnelConfig cfg_a;
    cfg_a.identity = id_a;
    cfg_a.local_ip = IP_A;
    cfg_a.local_prefix = 24;
    cfg_a.listen_port = PORT_A;
    cfg_a.peers = {
        { id_b.node_id, id_b.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_B),
          { allow(10, 20, 0, 0, 24) } },
        // Cross-network bootstrap candidate: C is on net2. The connect loop
        // will keep trying, but C's Session Manager must refuse the handshake.
        { id_c.node_id, id_c.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_C),
          { allow(10, 30, 0, 0, 24) } },
    };

    TunnelConfig cfg_b;
    cfg_b.identity = id_b;
    cfg_b.local_ip = IP_B;
    cfg_b.local_prefix = 24;
    cfg_b.listen_port = PORT_B;
    cfg_b.peers = {
        { id_a.node_id, id_a.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_A),
          { allow(10, 10, 0, 0, 24) } },
    };

    TunnelConfig cfg_c;
    cfg_c.identity = id_c;
    cfg_c.local_ip = IP_C;
    cfg_c.local_prefix = 24;
    cfg_c.listen_port = PORT_C;
    cfg_c.peers = {
        { id_a.node_id, id_a.keypair.public_key,
          Endpoint::from_parts(127, 0, 0, 1, PORT_A),
          { allow(10, 10, 0, 0, 24) } },
    };

    Tunnel tunnel_a;
    Tunnel tunnel_b;
    Tunnel tunnel_c;

    if (!tunnel_a.start(cfg_a, "Aegis 10.10.0.1") ||
        !tunnel_b.start(cfg_b, "Aegis 10.20.0.1") ||
        !tunnel_c.start(cfg_c, "Aegis 10.30.0.1")) {
        fprintf(stderr, "[segmentation-test] FAIL: a tunnel failed to start\n");
        tunnel_a.stop();
        tunnel_b.stop();
        tunnel_c.stop();
        return 1;
    }
    printf("[segmentation-test] all three nodes up\n");

    bool pass = true;

    // ---- phase 1: presence must cross networks ------------------------------
    // C (net2) must be visible to A and B (net1), and A/B visible to C.
    printf("[segmentation-test] phase 1: presence crosses networks (visible, unreachable)\n");
    auto presence_ok = [&]() {
        auto pa = tunnel_a.presences();
        auto pb = tunnel_b.presences();
        auto pc = tunnel_c.presences();
        return pa.count(id_c.node_id) && pb.count(id_c.node_id) &&
               pc.count(id_a.node_id) && pc.count(id_b.node_id);
    };
    bool seen = false;
    for (int i = 0; i < 40 && !seen; i++) {  // up to 8s (announce every 2s)
        if (presence_ok()) { seen = true; break; }
        Sleep(200);
    }
    if (!seen) {
        fprintf(stderr, "[segmentation-test] FAIL: cross-network presence not seen\n");
        pass = false;
    } else {
        auto pc = tunnel_c.presences();
        auto pa = tunnel_a.presences();
        printf("[segmentation-test] A sees net2 node C (net %02x): YES\n",
               pa[id_c.node_id].network_id[0]);
        printf("[segmentation-test] C sees net1 nodes A,B: YES\n");
        printf("[segmentation-test] presence crossing networks: OK\n");
    }

    // ---- phase 2: same-network session forms, cross-network never ------------
    printf("[segmentation-test] phase 2: A<->B session forms, A<->C must not\n");
    bool ab = wait_for_established(tunnel_a.peers(), id_b.node_id, 40) &&
              wait_for_established(tunnel_b.peers(), id_a.node_id, 40);
    if (!ab) {
        fprintf(stderr, "[segmentation-test] FAIL: net1 session A<->B never established\n");
        pass = false;
    } else {
        printf("[segmentation-test] A<->B established (same network): OK\n");
    }

    // Give A's connect loop a real chance to try C (and C's to try A), then
    // verify neither side ever established a cross-network session.
    Sleep(6000);
    bool cross_a = tunnel_a.session_established(id_c.node_id);
    bool cross_c = tunnel_c.session_established(id_a.node_id);
    if (cross_a || cross_c) {
        fprintf(stderr, "[segmentation-test] FAIL: cross-network session formed "
                        "(A<->C) — the gate did not hold\n");
        pass = false;
    } else {
        printf("[segmentation-test] no A<->C session despite configured candidate: OK\n");
    }

    // No route toward net2's prefix may exist on net1 nodes.
    auto has_route = [](const RoutingEngine& re, uint32_t prefix, uint8_t plen) {
        for (const auto& r : re.routes())
            if (r.prefix == prefix && r.prefix_length == plen)
                return true;
        return false;
    };
    if (has_route(tunnel_a.routing(), allow(10, 30, 0, 0, 24).prefix, 24)) {
        fprintf(stderr, "[segmentation-test] FAIL: net1 node A has a route toward net2 prefix\n");
        pass = false;
    } else {
        printf("[segmentation-test] no route toward net2 prefix on net1 node A: OK\n");
    }

    // ---- phase 3: net1 traffic still flows -----------------------------------
    if (pass) {
        printf("[segmentation-test] phase 3: net1 A<->B UDP round-trip\n");
        add_route_if("10.20.0.0", "255.255.255.0", "10.10.0.1", tunnel_a.interface_index());
        add_route_if("10.20.0.1", "255.255.255.255", "10.10.0.1", tunnel_a.interface_index());
        add_route_if("10.10.0.0", "255.255.255.0", "10.20.0.1", tunnel_b.interface_index());
        add_route_if("10.10.0.1", "255.255.255.255", "10.20.0.1", tunnel_b.interface_index());

        pass = udp_round_trip(IP_A, IP_B, "net1 A->B") && pass;

        delete_route("10.20.0.0", "255.255.255.0", "10.10.0.1");
        delete_route("10.20.0.1", "255.255.255.255", "10.10.0.1");
        delete_route("10.10.0.0", "255.255.255.0", "10.20.0.1");
        delete_route("10.10.0.1", "255.255.255.255", "10.20.0.1");
    }

    tunnel_a.stop();
    tunnel_b.stop();
    tunnel_c.stop();

    if (pass) {
        printf("[segmentation-test] *** ALL PASS ***\n");
        return 0;
    }
    fprintf(stderr, "[segmentation-test] *** FAIL ***\n");
    return 1;
}
