#include "aegis/adapter/adapter.hpp"
#include "aegis/platform/platform.hpp"
#include "aegis/transport/transport.hpp"
#include "aegis/crypto/x25519.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <vector>

// UDP packet: 10.10.0.2:12345 -> 10.10.0.1:9999, payload "hello" (5 bytes)
// Total 33 bytes: 20 IP + 8 UDP + 5 payload
// IP: tot_len=33(0x21), id=1, ttl=64, proto=17(UDP), csum=0x66b5
// UDP: sport=12345, dport=9999, len=13(0x0d), csum=0x50a3
static const uint8_t UDP_TEST_PACKET[] = {
    0x45, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x66, 0xb5, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x30, 0x39, 0x27, 0x0f, 0x00, 0x0d, 0x50, 0xa3,
    0x68, 0x65, 0x6c, 0x6c, 0x6f};

// ICMP Echo Request:  10.10.0.2 -> 10.10.0.1
// IP:    id=0xabcd, ttl=64, checksum=0xbadd
// ICMP:  type=8(echo), id=1, seq=1, payload=32 zero bytes, checksum=0xf7fd
static const uint8_t PING_TEST_PACKET[] = {
    0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd, 0x00, 0x00,
    0x40, 0x01, 0xba, 0xdd, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x08, 0x00, 0xf7, 0xfd, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static bool parse_hex(const char* hex, std::vector<uint8_t>& out) {
    size_t len = std::strlen(hex);
    if (len % 2 != 0) return false;
    out.resize(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char buf[3] = {hex[i], hex[i + 1], 0};
        char* end;
        unsigned long v = std::strtoul(buf, &end, 16);
        if (*end != 0) return false;
        out[i / 2] = (uint8_t)v;
    }
    return true;
}

static void print_usage(const char* prog) {
    printf("usage: %s [--listen | --inject <hex> | --ping-test | --transport-test | --crypto-test]\n\n", prog);
    printf("  --listen           create adapter at 10.10.0.1/24 and print packets for 30s\n");
    printf("  --inject <hex>     inject a raw hex-encoded IP packet, then read one reply\n");
    printf("  --ping-test        inject a UDP packet, confirm OS listener receives it\n");
    printf("  --transport-test   loopback UDP send/receive via Transport class\n");
}

// ---- crypto-test ------------------------------------------------------------
static int run_crypto_test() {
    printf("[crypto-test] generating keypairs...\n");

    X25519KeyPair alice = x25519_generate_keypair();
    X25519KeyPair bob   = x25519_generate_keypair();

    // Check keys are non-zero
    auto key_all_zero = [](const X25519Key& k) {
        for (auto b : k) if (b != 0) return false;
        return true;
    };

    if (key_all_zero(alice.private_key) || key_all_zero(alice.public_key)) {
        fprintf(stderr, "[crypto-test] FAIL — alice keypair generation returned all zeros\n");
        return 1;
    }
    if (key_all_zero(bob.private_key) || key_all_zero(bob.public_key)) {
        fprintf(stderr, "[crypto-test] FAIL — bob keypair generation returned all zeros\n");
        return 1;
    }

    printf("[crypto-test] alice priv: ");
    for (auto b : alice.private_key) printf("%02x", b);
    printf("\n[crypto-test] alice pub:  ");
    for (auto b : alice.public_key) printf("%02x", b);

    printf("\n[crypto-test] bob priv:   ");
    for (auto b : bob.private_key) printf("%02x", b);
    printf("\n[crypto-test] bob pub:    ");
    for (auto b : bob.public_key) printf("%02x", b);
    printf("\n");

    // Derive from both directions
    printf("[crypto-test] deriving shared secret (A-side)...\n");
    auto s_alice = x25519_derive_shared_secret(alice.private_key, bob.public_key);
    if (!s_alice.has_value()) {
        fprintf(stderr, "[crypto-test] FAIL — alice-side derivation returned nullopt\n");
        return 1;
    }

    printf("[crypto-test] deriving shared secret (B-side)...\n");
    auto s_bob = x25519_derive_shared_secret(bob.private_key, alice.public_key);
    if (!s_bob.has_value()) {
        fprintf(stderr, "[crypto-test] FAIL — bob-side derivation returned nullopt\n");
        return 1;
    }

    printf("[crypto-test] secret (A-side): ");
    for (auto b : *s_alice) printf("%02x", b);
    printf("\n[crypto-test] secret (B-side): ");
    for (auto b : *s_bob) printf("%02x", b);
    printf("\n");

    // Verify match
    bool match = true;
    for (size_t i = 0; i < X25519_KEY_SIZE; i++)
        if ((*s_alice)[i] != (*s_bob)[i]) { match = false; break; }

    if (!match) {
        fprintf(stderr, "[crypto-test] FAIL — shared secrets do not match\n");
        return 1;
    }

    printf("[crypto-test] *** PASS *** shared secret matches from both sides\n");
    return 0;
}

// ---- transport-test --------------------------------------------------------
static int run_transport_test() {
    printf("[transport-test] starting\n");

    Transport tx;
    Transport rx;

    if (!tx.bind(7001)) {
        fprintf(stderr, "[transport-test] tx bind failed\n");
        return 1;
    }
    printf("[transport-test] tx bound to port 7001\n");

    if (!rx.bind(7002)) {
        fprintf(stderr, "[transport-test] rx bind failed\n");
        return 1;
    }
    printf("[transport-test] rx bound to port 7002\n");

    // State shared between callback and main thread
    bool received = false;
    std::vector<uint8_t> recv_data;
    Endpoint recv_from{};
    std::mutex mtx;
    std::condition_variable cv;

    if (!rx.start_receive([&](const uint8_t* data, size_t len, Endpoint sender) {
        std::lock_guard<std::mutex> lock(mtx);
        received = true;
        recv_data.assign(data, data + len);
        recv_from = sender;
        cv.notify_one();
    })) {
        fprintf(stderr, "[transport-test] rx start_receive failed\n");
        tx.close();
        rx.close();
        return 1;
    }

    // Send known payload
    const char* payload = "hello-transport";
    size_t payload_len = std::strlen(payload);
    Endpoint dest = Endpoint::from_parts(127, 0, 0, 1, 7002);
    if (!tx.send((const uint8_t*)payload, payload_len, dest)) {
        fprintf(stderr, "[transport-test] tx.send failed\n");
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }
    printf("[transport-test] sent %zu bytes to 127.0.0.1:7002\n", payload_len);

    // Wait for receipt (1s timeout)
    {
        std::unique_lock<std::mutex> lock(mtx);
        if (!cv.wait_for(lock, std::chrono::seconds(1), [&] { return received; })) {
            fprintf(stderr, "[transport-test] FAIL — rx timed out, no packet received\n");
            rx.stop_receive();
            tx.close();
            rx.close();
            return 1;
        }
    }

    // Verify payload
    bool payload_ok = (recv_data.size() == payload_len &&
                       std::memcmp(recv_data.data(), payload, payload_len) == 0);
    if (!payload_ok) {
        fprintf(stderr, "[transport-test] FAIL — payload mismatch\n");
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }

    // Verify sender endpoint (127.0.0.1:7001)
    Endpoint expected_sender = Endpoint::from_parts(127, 0, 0, 1, 7001);
    if (!(recv_from == expected_sender)) {
        fprintf(stderr, "[transport-test] FAIL — sender mismatch: got %08x:%04x, expected %08x:%04x\n",
                recv_from.ip, recv_from.port, expected_sender.ip, expected_sender.port);
        rx.stop_receive();
        tx.close();
        rx.close();
        return 1;
    }

    printf("[transport-test] *** PASS *** received %zu bytes from 127.0.0.1:7001: \"%s\"\n",
           recv_data.size(), recv_data.data());

    rx.stop_receive();
    tx.close();
    rx.close();
    return 0;
}

// ---- main ------------------------------------------------------------------
int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("[main] starting\n");

    if (!platform_init_winsock()) return 1;

    // ---- parse mode --------------------------------------------------------
    bool mode_listen       = false;
    bool mode_inject       = false;
    bool mode_ping_test    = false;
    bool mode_transport_test = false;
    bool mode_crypto_test  = false;
    std::vector<uint8_t> inject_data;

    if (argc < 2) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--listen") == 0) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--ping-test") == 0) {
        mode_ping_test = true;
    } else if (std::strcmp(argv[1], "--transport-test") == 0) {
        mode_transport_test = true;
    } else if (std::strcmp(argv[1], "--crypto-test") == 0) {
        mode_crypto_test = true;
    } else if (argc > 2 && std::strcmp(argv[1], "--inject") == 0) {
        if (!parse_hex(argv[2], inject_data)) {
            fprintf(stderr, "error: invalid hex string\n");
            platform_cleanup_winsock();
            return 1;
        }
        mode_inject = true;
    } else {
        print_usage(argv[0]);
        platform_cleanup_winsock();
        return 1;
    }

    // ---- modes that don't need adapter or winsock --------------------------
    if (mode_crypto_test) {
        return run_crypto_test();
    }

    // ---- transport-test (no adapter needed) --------------------------------
    if (mode_transport_test) {
        int ret = run_transport_test();
        platform_cleanup_winsock();
        return ret;
    }

    // ---- modes requiring adapter: check admin + create adapter ------------
    if (!platform_is_admin()) {
        fprintf(stderr, "error: must run as administrator\n");
        platform_cleanup_winsock();
        return 1;
    }

    Adapter adapter;
    if (!adapter.create()) {
        fprintf(stderr, "error: adapter creation failed\n");
        platform_cleanup_winsock();
        return 1;
    }

    // ---- inject / ping-test ------------------------------------------------
    if (mode_ping_test || mode_inject) {
        const uint8_t* data;
        size_t len;
        if (mode_ping_test) {
            SOCKET listener = socket(AF_INET, SOCK_DGRAM, 0);
            bool listener_ok = false;
            if (listener != INVALID_SOCKET) {
                struct sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
                addr.sin_port = htons(9999);
                listener_ok = (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 0);
                if (listener_ok)
                    printf("[main] listening on 10.10.0.1:9999\n");
            }

            char rule_name[] = "AegisTempPingTest";
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall add rule name=%s dir=in"
                " program=\"%s\" protocol=udp localport=9999 action=allow",
                rule_name, exe_path);
            int fw_ret = system(cmd);
            printf("[main] firewall rule add returned %d\n", fw_ret);

            std::vector<uint8_t> drain;
            for (int i = 0; i < 5; i++) {
                if (!adapter.read_packet(drain, 200)) break;
            }

            data = UDP_TEST_PACKET;
            len  = sizeof(UDP_TEST_PACKET);
            printf("[main] ping-test: injecting %zu bytes:\n      ", len);
            for (size_t i = 0; i < len; i++)
                printf("%02x%c", data[i], (i % 16 == 15) ? '\n' : ' ');
            putchar('\n');

            if (!adapter.write_packet({data, data + len})) {
                fprintf(stderr, "error: write_packet failed\n");
                adapter.close();
                platform_cleanup_winsock();
                return 1;
            }
            printf("[main] write OK\n");

            if (listener_ok) {
                DWORD timeout = 5000;
                setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO,
                           (const char*)&timeout, sizeof(timeout));
                char buf[64] = {};
                struct sockaddr_in from = {};
                int fromlen = sizeof(from);
                int r = recvfrom(listener, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
                if (r > 0) {
                    buf[r] = 0;
                    printf("[main] *** INJECTION CONFIRMED *** listener received %d bytes"
                           " from %s:%d: \"%s\"\n",
                           r, inet_ntoa(from.sin_addr), ntohs(from.sin_port), buf);
                } else {
                    int err = WSAGetLastError();
                    printf("[main] listener error %d (0x%x)"
                           " — injection may have failed\n", err, err);
                }
                closesocket(listener);
            }

            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall delete rule name=%s", rule_name);
            system(cmd);
        } else {
            data = inject_data.data();
            len  = inject_data.size();
            printf("[main] inject: injecting %zu bytes\n", len);

            if (!adapter.write_packet({data, data + len})) {
                fprintf(stderr, "error: write_packet failed\n");
                adapter.close();
                platform_cleanup_winsock();
                return 1;
            }
            printf("[main] write OK\n");
        }

        // Send a packet from the OS through Wintun and verify typed parsing
        printf("[main] testing typed parser with OS outbound traffic...\n");
        {
            SOCKET sender = socket(AF_INET, SOCK_DGRAM, 0);
            if (sender != INVALID_SOCKET) {
                struct sockaddr_in local = {};
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
                local.sin_port = htons(54321);
                bind(sender, (struct sockaddr*)&local, sizeof(local));

                struct sockaddr_in dest = {};
                dest.sin_family = AF_INET;
                dest.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 2);
                dest.sin_port = htons(9999);
                const char* msg = "probe";
                sendto(sender, msg, 5, 0, (struct sockaddr*)&dest, sizeof(dest));
                printf("[main] OS sent UDP to 10.10.0.2:9999\n");
                closesocket(sender);
            }

            std::vector<uint8_t> reply;
            for (int i = 0; i < 20; i++) {
                reply.clear();
                if (!adapter.read_packet(reply, 250)) continue;
                Adapter::print_packet(reply.data(), reply.size());
            }
        }

        adapter.close();
        platform_cleanup_winsock();
        return 0;
    }

    // ---- listen ------------------------------------------------------------
    printf("[main] listening for packets (30s timeout)...\n");
    printf("[main]   try:  ping 10.10.0.2   (from another terminal)\n");

    std::atomic<bool> done{false};
    std::thread reader([&]() {
        std::vector<uint8_t> buf;
        while (!done) {
            buf.clear();
            if (adapter.read_packet(buf))
                Adapter::print_packet(buf.data(), buf.size());
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(30));
    done = true;
    adapter.close();
    reader.join();

    printf("[main] listen complete\n");
    platform_cleanup_winsock();
    return 0;
}
