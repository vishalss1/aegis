#include "aegis/tunnel/tunnel_test.hpp"
#include "aegis/tunnel/tunnel.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>

namespace {

const uint32_t IP_A = htonl((10u << 24) | (10u << 16) | (0u << 8) | 1u);
const uint32_t IP_B = htonl((10u << 24) | (20u << 16) | (0u << 8) | 1u);
const uint16_t PORT_A = 51820;
const uint16_t PORT_B = 51821;

// The /32 host routes below are what force the test's UDP packets OUT of the
// adapters and through the encrypted tunnel. Without them, Windows delivers
// to a local address over its implicit loopback host route and the packet
// never touches the tunnel (which made plain `ping` ambiguous on one host).
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

bool udp_round_trip() {
    SOCKET listener = socket(AF_INET, SOCK_DGRAM, 0);
    if (listener == INVALID_SOCKET) {
        fprintf(stderr, "[tunnel-test] FAIL: socket(listener): %d\n", WSAGetLastError());
        return false;
    }
    struct sockaddr_in laddr = {};
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = IP_B;
    laddr.sin_port = 0;
    if (bind(listener, (struct sockaddr*)&laddr, sizeof(laddr)) != 0) {
        fprintf(stderr, "[tunnel-test] FAIL: bind listener on 10.20.0.1: %d "
                "(close any stale test sockets holding the port first)\n",
                WSAGetLastError());
        closesocket(listener);
        return false;
    }
    int llen = sizeof(laddr);
    getsockname(listener, (struct sockaddr*)&laddr, &llen);
    uint16_t listener_port = ntohs(laddr.sin_port);

    SOCKET sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender == INVALID_SOCKET) {
        fprintf(stderr, "[tunnel-test] FAIL: socket(sender): %d\n", WSAGetLastError());
        closesocket(listener);
        return false;
    }
    struct sockaddr_in saddr = {};
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = IP_A;
    saddr.sin_port = 0;
    if (bind(sender, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
        fprintf(stderr, "[tunnel-test] FAIL: bind sender on 10.10.0.1: %d "
                "(close any stale test sockets holding the port first)\n",
                WSAGetLastError());
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

    // --- forward: 10.10.0.1 -> 10.20.0.1 -------------------------------------
    // /32 route forces it out adapter A -> encrypted tunnel -> adapter B.
    const char* hello = "hello-tunnel";
    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = IP_B;
    dst.sin_port = htons(listener_port);
    if (sendto(sender, hello, (int)std::strlen(hello), 0,
               (struct sockaddr*)&dst, sizeof(dst)) == SOCKET_ERROR) {
        fprintf(stderr, "[tunnel-test] FAIL: forward sendto: %d\n", WSAGetLastError());
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    printf("[tunnel-test] forward send  -> 10.20.0.1:%u\n", listener_port);

    char buf[64] = {};
    struct sockaddr_in from = {};
    int fromlen = sizeof(from);
    int r = recvfrom(listener, buf, sizeof(buf), 0,
                     (struct sockaddr*)&from, &fromlen);
    if (r == (int)std::strlen(hello) && std::memcmp(buf, hello, std::strlen(hello)) == 0) {
        printf("[tunnel-test] forward recv  <- 10.20.0.1:%u via tunnel: \"%.*s\"\n",
               listener_port, r, buf);
    } else {
        fprintf(stderr, "[tunnel-test] FAIL: forward recv: got %d bytes (err %d), expected \"%s\"\n",
                r, WSAGetLastError(), hello);
        closesocket(listener);
        closesocket(sender);
        return false;
    }

    // --- return: listener replies to the sender -----------------------------
    // /32 route for 10.10.0.1 forces the reply out adapter B -> tunnel -> adapter A.
    const char* pong = "pong";
    if (sendto(listener, pong, (int)std::strlen(pong), 0,
               (struct sockaddr*)&from, fromlen) == SOCKET_ERROR) {
        fprintf(stderr, "[tunnel-test] FAIL: return sendto: %d\n", WSAGetLastError());
        closesocket(listener);
        closesocket(sender);
        return false;
    }
    printf("[tunnel-test] return send  -> %s:%d\n",
           inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    r = recvfrom(sender, buf, sizeof(buf), 0,
                 (struct sockaddr*)&from, &fromlen);
    if (r == (int)std::strlen(pong) && std::memcmp(buf, pong, std::strlen(pong)) == 0) {
        printf("[tunnel-test] return recv  <- 10.10.0.1:%u via tunnel: \"%.*s\"\n",
               sender_port, r, buf);
    } else {
        fprintf(stderr, "[tunnel-test] FAIL: return recv: got %d bytes (err %d), expected \"%s\"\n",
                r, WSAGetLastError(), pong);
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
    printf("[tunnel-test] topology: tunnel A (10.10.0.1/24 :51820) <-> tunnel B (10.20.0.1/24 :51821) over 127.0.0.1\n");
    printf("[tunnel-test] /32 host routes suppress local loopback delivery so UDP must transit the encrypted tunnel\n");
    printf("[tunnel-test] note: UDP only - ICMP cannot be verified on a single host (Windows drops looped-back echo replies)\n");

    TunnelConfig cfg_a;
    cfg_a.local_ip = IP_A;
    cfg_a.local_prefix = 24;
    cfg_a.listen_port = PORT_A;
    cfg_a.peer_endpoint = Endpoint::from_parts(127, 0, 0, 1, PORT_B);

    TunnelConfig cfg_b;
    cfg_b.local_ip = IP_B;
    cfg_b.local_prefix = 24;
    cfg_b.listen_port = PORT_B;
    cfg_b.peer_endpoint = Endpoint::from_parts(127, 0, 0, 1, PORT_A);

    Tunnel tunnel_a;
    Tunnel tunnel_b;

    // Tunnel::start() blocks on the handshake, so both must start concurrently
    // or the initiator exhausts its retries before the responder is listening.
    bool ok_a = false, ok_b = false;
    std::thread ta([&] { ok_a = tunnel_a.start(cfg_a, "Aegis 10.10.0.1"); });
    std::thread tb([&] { ok_b = tunnel_b.start(cfg_b, "Aegis 10.20.0.1"); });
    ta.join();
    tb.join();

    if (!ok_a || !ok_b) {
        fprintf(stderr, "[tunnel-test] FAIL: tunnel start (A=%d, B=%d)\n", ok_a, ok_b);
        tunnel_a.stop();
        tunnel_b.stop();
        return 1;
    }
    printf("[tunnel-test] sessions established on both tunnels\n");

    add_route("10.20.0.0", "255.255.255.0", "10.10.0.1");
    add_route("10.10.0.0", "255.255.255.0", "10.20.0.1");
    add_route("10.20.0.1", "255.255.255.255", "10.10.0.1");
    add_route("10.10.0.1", "255.255.255.255", "10.20.0.1");

    bool pass = udp_round_trip();

    delete_route("10.20.0.1", "255.255.255.255", "10.10.0.1");
    delete_route("10.10.0.1", "255.255.255.255", "10.20.0.1");
    delete_route("10.20.0.0", "255.255.255.0", "10.10.0.1");
    delete_route("10.10.0.0", "255.255.255.0", "10.20.0.1");

    tunnel_a.stop();
    tunnel_b.stop();

    if (pass) {
        printf("[tunnel-test] *** ALL PASS ***\n");
        return 0;
    }
    fprintf(stderr, "[tunnel-test] *** FAIL ***\n");
    return 1;
}
