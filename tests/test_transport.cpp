#include "aegis/transport/transport.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (!platform_init_winsock()) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    printf("--- transport tests ---\n");

    // ---- 1. Round-trip send/receive ---------------------------------------
    {
        Transport tx;
        Transport rx;
        bool ok = true;

        ok = ok && tx.bind(7101);
        ok = ok && rx.bind(7102);
        CHECK(ok);
        CHECK(tx.local_port() == 7101);
        CHECK(rx.local_port() == 7102);
        CHECK(tx.is_open());
        CHECK(rx.is_open());

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
            CHECK(!"rx.start_receive failed");
        } else {
            // Give recv thread time to enter recvfrom
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            const char* payload = "transport-ok";
            size_t plen = std::strlen(payload);
            Endpoint dest = Endpoint::from_parts(127, 0, 0, 1, 7102);
            CHECK(tx.send((const uint8_t*)payload, plen, dest));

            {
                std::unique_lock<std::mutex> lock(mtx);
                CHECK(cv.wait_for(lock, std::chrono::seconds(2), [&] { return received; }));
            }

            if (received) {
                CHECK(recv_data.size() == plen);
                CHECK(std::memcmp(recv_data.data(), payload, plen) == 0);

                Endpoint expected_sender = Endpoint::from_parts(127, 0, 0, 1, 7101);
                CHECK(recv_from == expected_sender);
            }

            rx.stop_receive();
        }

        tx.close();
        rx.close();
    }

    // ---- 2. Wrong port should not receive ----------------------------------
    {
        Transport tx;
        Transport rx;
        bool ok = true;

        ok = ok && tx.bind(7103);
        ok = ok && rx.bind(7104);
        CHECK(ok);

        bool received = false;
        std::mutex mtx;
        std::condition_variable cv;

        if (!rx.start_receive([&](const uint8_t*, size_t, Endpoint) {
            std::lock_guard<std::mutex> lock(mtx);
            received = true;
            cv.notify_one();
        })) {
            CHECK(!"rx.start_receive failed");
        } else {
            // Send to wrong port (7105 instead of 7104)
            const char* payload = "wrong-port";
            Endpoint wrong_dest = Endpoint::from_parts(127, 0, 0, 1, 7105);
            CHECK(tx.send((const uint8_t*)payload, std::strlen(payload), wrong_dest));

            // Wait briefly — should NOT receive
            {
                std::unique_lock<std::mutex> lock(mtx);
                bool got = cv.wait_for(lock, std::chrono::milliseconds(500), [&] { return received; });
                CHECK(!got);
            }

            rx.stop_receive();
        }

        tx.close();
        rx.close();
    }

    // ---- 3. Close without bind (is_open false) -----------------------------
    {
        Transport t;
        CHECK(!t.is_open());
        CHECK(t.local_port() == 0);
        t.close();
        CHECK(!t.is_open());
    }

    // ---- 4. Send on unbound socket returns false ---------------------------
    {
        Transport t;
        CHECK(!t.send((const uint8_t*)"test", 4, Endpoint::from_parts(127, 0, 0, 1, 9999)));
    }

    printf("\n%d / %d passed\n", passed, tests);
    platform_cleanup_winsock();
    return (passed == tests) ? 0 : 1;
}
