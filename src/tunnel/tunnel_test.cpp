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
// Ports sit below Windows' ephemeral/excluded range (49k+). The original
// 51820-51822 land inside the dynamic "Administered port exclusions" band
// (Windows reserves ranges there on the fly), which intermittently failed
// bind with WSAEACCES.
const uint16_t PORT_A = 45120;
const uint16_t PORT_B = 45121;
const uint16_t PORT_C = 45122;

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
