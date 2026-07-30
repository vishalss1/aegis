#include "aegis/adapter/adapter.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>

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
    printf("usage: %s [--listen | --inject <hex> | --ping-test]\n\n", prog);
    printf("  --listen       create adapter at 10.10.0.1/24 and print packets for 30s\n");
    printf("  --inject <hex> inject a raw hex-encoded IP packet, then read one reply\n");
    printf("  --ping-test    inject an ICMP Echo Request, prove both directions\n");
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("[main] starting\n");

    if (!platform_init_winsock()) return 1;

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

    // ---- parse mode --------------------------------------------------------
    bool mode_listen    = false;
    bool mode_inject    = false;
    bool mode_ping_test = false;
    std::vector<uint8_t> inject_data;

    if (argc < 2) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--listen") == 0) {
        mode_listen = true;
    } else if (std::strcmp(argv[1], "--ping-test") == 0) {
        mode_ping_test = true;
    } else if (argc > 2 && std::strcmp(argv[1], "--inject") == 0) {
        if (!parse_hex(argv[2], inject_data)) {
            fprintf(stderr, "error: invalid hex string\n");
            adapter.close();
            platform_cleanup_winsock();
            return 1;
        }
        mode_inject = true;
    } else {
        print_usage(argv[0]);
        adapter.close();
        platform_cleanup_winsock();
        return 1;
    }

    // ---- inject / ping-test ------------------------------------------------
    if (mode_ping_test || mode_inject) {
        const uint8_t* data;
        size_t len;
        if (mode_ping_test) {
            // Create UDP listener on 10.10.0.1:9999 to receive injected packet
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

            // Drain init packets then inject UDP through Wintun
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

            // Add temp firewall rule allowing inbound UDP 9999 for our binary
            char rule_name[] = "AegisTempPingTest";
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall add rule name=%s dir=in"
                " program=\"%s\" protocol=udp localport=9999 action=allow >nul 2>nul",
                rule_name, exe_path);
            system(cmd);

            // Check if OS socket received the injected packet
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

            // Remove the temp firewall rule
            snprintf(cmd, sizeof(cmd),
                "netsh advfirewall firewall delete rule name=%s >nul 2>nul", rule_name);
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

            // The OS-routed packet should appear on Wintun read
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
