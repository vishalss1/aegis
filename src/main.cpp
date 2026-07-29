#include "aegis/adapter.hpp"
#include "aegis/platform.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <chrono>

// UDP packet: 10.10.0.2:12345 -> 10.10.0.1:9999, payload "hello" (5 bytes)
// IP: id=1, ttl=64, checksum=0x66a9 (proto 17 = UDP)
static const uint8_t UDP_TEST_PACKET[] = {
    0x45, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x66, 0xa9, 0x0a, 0x0a, 0x00, 0x02,
    0x0a, 0x0a, 0x00, 0x01,
    0x30, 0x39, 0x27, 0x0f, 0x00, 0x19, 0x00, 0x00,
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
            // Send a packet through the OS socket API and verify it appears on Wintun
            SOCKET sender = socket(AF_INET, SOCK_DGRAM, 0);
            if (sender != INVALID_SOCKET) {
                struct sockaddr_in local = {};
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
                local.sin_port = htons(12345);
                if (bind(sender, (struct sockaddr*)&local, sizeof(local)) == 0)
                    printf("[main] sender bound to 10.10.0.1:12345\n");
            }

            struct sockaddr_in dest = {};
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 2);
            dest.sin_port = htons(9999);
            const char* msg = "hello";
            int sent = sendto(sender, msg, 5, 0, (struct sockaddr*)&dest, sizeof(dest));
            if (sent > 0)
                printf("[main] OS sent %d bytes to 10.10.0.2:9999\n", sent);
            else
                printf("[main] sendto failed (error %d)\n", WSAGetLastError());
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

        // Read from Wintun — the OS-routed packet should appear here
        printf("[main] reading from Wintun for 5s...\n");
        std::vector<uint8_t> reply;
        for (int i = 0; i < 20; i++) {
            reply.clear();
            if (!adapter.read_packet(reply, 250)) break;
            printf("[main] read %zu bytes\n", reply.size());
            Adapter::print_packet(reply.data(), reply.size());
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
