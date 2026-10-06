#include "aegis/transport/transport.hpp"
#include "aegis/transport/send_queue.hpp"
#include "aegis/transport/handshake_rate_limiter.hpp"
#include "aegis/transport/handshake_cookie.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

static int tests  = 0;
static int passed = 0;

class ManualClock final : public ProtocolClock {
public:
    [[nodiscard]] time_point now() const noexcept override { return now_; }
    void advance(std::chrono::milliseconds duration) { now_ += duration; }

private:
    time_point now_{};
};

class IncrementingRandom final : public RandomSource {
public:
    [[nodiscard]] bool fill(std::span<uint8_t> output) override {
        for (size_t i = 0; i < output.size(); ++i)
            output[i] = static_cast<uint8_t>(generation_ + i);
        ++generation_;
        return true;
    }

private:
    uint8_t generation_ = 1;
};

class FailingRandom final : public RandomSource {
public:
    [[nodiscard]] bool fill(std::span<uint8_t>) override { return false; }
};

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

    // ---- 5. Datagram budgets reject oversized sends and receives -----------
    {
        Transport tx;
        Transport rx;
        CHECK(tx.set_max_datagram_size(9));
        CHECK(rx.set_max_datagram_size(8));
        CHECK(tx.max_datagram_size() == 9);
        CHECK(rx.max_datagram_size() == 8);
        CHECK(!tx.set_max_datagram_size(0));
        CHECK(!tx.set_max_datagram_size(IPV4_UDP_MAX_DATAGRAM_SIZE + 1));
        CHECK(tx.max_datagram_size() == 9);

        bool ok = tx.bind(7106) && rx.bind(7107);
        CHECK(ok);
        bool received = false;
        size_t received_size = 0;
        std::mutex mtx;
        std::condition_variable cv;

        if (!rx.start_receive(
                [&](const uint8_t*, size_t len, Endpoint) {
                    std::lock_guard<std::mutex> lock(mtx);
                    received = true;
                    received_size = len;
                    cv.notify_one();
                })) {
            CHECK(!"rx.start_receive failed");
        } else {
            const std::array<uint8_t, 10> payload{};
            const Endpoint dest =
                Endpoint::from_parts(127, 0, 0, 1, 7107);

            // Nine bytes fit the sender but exceed the receiver's budget.
            CHECK(tx.send(payload.data(), 9, dest));
            // The following exact-boundary datagram proves the prior one was
            // consumed and dropped before this callback was delivered.
            CHECK(tx.send(payload.data(), 8, dest));
            {
                std::unique_lock<std::mutex> lock(mtx);
                CHECK(cv.wait_for(lock, std::chrono::seconds(2),
                                  [&] { return received; }));
            }
            CHECK(received_size == 8);
            CHECK(rx.oversize_receive_drops() == 1);

            CHECK(!tx.send(payload.data(), 10, dest));
            CHECK(tx.oversize_send_drops() == 1);
            rx.stop_receive();
        }

        tx.close();
        rx.close();
    }

    // ---- 6. Send queues enforce item/byte caps and drain peers fairly ------
    {
        SendQueueLimits limits;
        limits.data.max_items_per_peer = 2;
        limits.data.max_bytes_per_peer = 6;
        limits.data.max_items_global = 3;
        limits.data.max_bytes_global = 10;
        BoundedSendQueue queue(limits);
        const std::array<uint8_t, 4> payload{1, 2, 3, 4};

        CHECK(queue.enqueue(1, payload.data(), 3) == SendQueueResult::Queued);
        CHECK(queue.enqueue(1, payload.data(), 3) == SendQueueResult::Queued);
        CHECK(queue.enqueue(1, payload.data(), 1) ==
              SendQueueResult::PerPeerItemLimit);
        CHECK(queue.enqueue(2, payload.data(), 4) == SendQueueResult::Queued);
        CHECK(queue.enqueue(2, payload.data(), 1) ==
              SendQueueResult::GlobalItemLimit);
        CHECK(queue.size() == 3);
        CHECK(queue.bytes() == 10);
        CHECK(queue.peer_count() == 2);

        const auto first = queue.pop();
        const auto second = queue.pop();
        const auto third = queue.pop();
        CHECK(first && first->peer_key == 1 && first->bytes.size() == 3);
        CHECK(second && second->peer_key == 2 && second->bytes.size() == 4);
        CHECK(third && third->peer_key == 1 && third->bytes.size() == 3);
        CHECK(queue.empty());
        CHECK(!queue.pop().has_value());

        SendQueueLimits byte_limits;
        byte_limits.data.max_items_per_peer = 3;
        byte_limits.data.max_bytes_per_peer = 4;
        byte_limits.data.max_items_global = 4;
        byte_limits.data.max_bytes_global = 6;
        BoundedSendQueue byte_queue(byte_limits);
        CHECK(byte_queue.enqueue(1, payload.data(), 3) ==
              SendQueueResult::Queued);
        CHECK(byte_queue.enqueue(1, payload.data(), 2) ==
              SendQueueResult::PerPeerByteLimit);
        CHECK(byte_queue.enqueue(2, payload.data(), 3) ==
              SendQueueResult::Queued);
        CHECK(byte_queue.enqueue(3, payload.data(), 1) ==
              SendQueueResult::GlobalByteLimit);
        byte_queue.clear();
        CHECK(byte_queue.empty());
        CHECK(byte_queue.bytes() == 0);
        CHECK(byte_queue.peer_count() == 0);
    }

    // ---- 7. Control has reserved capacity and strict dequeue priority -------
    {
        CHECK(TRANSPORT_QUEUE_MAX_ITEMS_PER_PEER == 64);
        CHECK(TRANSPORT_QUEUE_MAX_BYTES_PER_PEER == 256 * 1024);
        CHECK(TRANSPORT_QUEUE_MAX_ITEMS_GLOBAL == 1024);
        CHECK(TRANSPORT_QUEUE_MAX_BYTES_GLOBAL == 4 * 1024 * 1024);

        SendQueueLimits limits;
        limits.data.max_items_per_peer = 1;
        limits.data.max_bytes_per_peer = 4;
        limits.data.max_items_global = 2;
        limits.data.max_bytes_global = 8;
        limits.control.max_items_per_peer = 1;
        limits.control.max_bytes_per_peer = 4;
        limits.control.max_items_global = 2;
        limits.control.max_bytes_global = 8;
        BoundedSendQueue queue(limits);
        const std::array<uint8_t, 2> payload{1, 2};

        CHECK(queue.enqueue(1, payload.data(), payload.size()) ==
              SendQueueResult::Queued);
        CHECK(queue.enqueue(1, payload.data(), payload.size()) ==
              SendQueueResult::PerPeerItemLimit);
        CHECK(queue.enqueue(
                  1, payload.data(), payload.size(), SendPriority::Control) ==
              SendQueueResult::Queued);
        CHECK(queue.enqueue(2, payload.data(), payload.size()) ==
              SendQueueResult::Queued);
        CHECK(queue.enqueue(
                  2, payload.data(), payload.size(), SendPriority::Control) ==
              SendQueueResult::Queued);
        CHECK(queue.data_size() == 2);
        CHECK(queue.control_size() == 2);

        const auto first = queue.pop();
        const auto second = queue.pop();
        const auto third = queue.pop();
        const auto fourth = queue.pop();
        CHECK(first && first->priority == SendPriority::Control &&
              first->peer_key == 1);
        CHECK(second && second->priority == SendPriority::Control &&
              second->peer_key == 2);
        CHECK(third && third->priority == SendPriority::Data &&
              third->peer_key == 1);
        CHECK(fourth && fourth->priority == SendPriority::Data &&
              fourth->peer_key == 2);
        CHECK(queue.empty());
    }

    // ---- 8. Queue-drop metrics classify traffic and reset cleanly ----------
    {
        TransportQueueMetrics metrics;
        CHECK(metrics.stats().total() == 0);
        metrics.record_drop(SendPriority::Data);
        metrics.record_drop(SendPriority::Data);
        metrics.record_drop(SendPriority::Control);
        const auto drops = metrics.stats();
        CHECK(drops.data == 2);
        CHECK(drops.control == 1);
        CHECK(drops.total() == 3);
        metrics.reset();
        CHECK(metrics.stats().total() == 0);
    }

    // ---- 9. Handshake limiter: per-IP and global fixed-window budgets ------
    {
        ManualClock clock;
        HandshakeRateLimitConfig config;
        config.per_source_limit = 2;
        config.global_limit = 3;
        config.max_sources = 4;
        config.window = std::chrono::milliseconds(1000);
        HandshakeRateLimiter limiter(clock, config);

        const Endpoint source_a = Endpoint::from_parts(10, 0, 0, 1, 4000);
        const Endpoint source_a_new_port = Endpoint::from_parts(10, 0, 0, 1, 5000);
        const Endpoint source_b = Endpoint::from_parts(10, 0, 0, 2, 4000);

        CHECK(limiter.allow(source_a));
        CHECK(limiter.allow(source_a_new_port));
        CHECK(!limiter.allow(source_a));
        CHECK(limiter.allow(source_b));
        CHECK(!limiter.allow(Endpoint::from_parts(10, 0, 0, 3, 4000)));

        clock.advance(std::chrono::milliseconds(1000));
        CHECK(limiter.allow(source_a));
        CHECK(limiter.tracked_sources() == 1);
    }

    // ---- 9. Handshake limiter: source tracking is bounded and expires ------
    {
        ManualClock clock;
        HandshakeRateLimitConfig config;
        config.per_source_limit = 10;
        config.global_limit = 10;
        config.max_sources = 2;
        config.window = std::chrono::milliseconds(500);
        HandshakeRateLimiter limiter(clock, config);

        CHECK(limiter.allow(Endpoint::from_parts(10, 0, 0, 1, 4000)));
        CHECK(limiter.allow(Endpoint::from_parts(10, 0, 0, 2, 4000)));
        CHECK(!limiter.allow(Endpoint::from_parts(10, 0, 0, 3, 4000)));
        CHECK(limiter.tracked_sources() == 2);

        clock.advance(std::chrono::milliseconds(500));
        CHECK(limiter.allow(Endpoint::from_parts(10, 0, 0, 3, 4000)));
        CHECK(limiter.tracked_sources() == 1);
    }

    // ---- 10. Stateless retry cookies bind endpoint, session, and INIT -------
    {
        ManualClock clock;
        IncrementingRandom random;
        HandshakeCookieConfig config;
        config.rotation_interval = std::chrono::milliseconds(100);
        HandshakeCookieManager cookies(clock, random, config);
        const Endpoint source = Endpoint::from_parts(10, 20, 30, 40, 5000);
        const std::array<uint8_t, 5> init{1, 2, 3, 4, 5};
        constexpr uint32_t session_id = 0x12345678;

        const auto first = cookies.issue(source, session_id, init);
        CHECK(first.has_value());
        CHECK(first && cookies.verify(*first, source, session_id, init));
        CHECK(first && !cookies.verify(
            *first, Endpoint::from_parts(10, 20, 30, 40, 5001),
            session_id, init));
        CHECK(first && !cookies.verify(*first, source, session_id + 1, init));
        auto changed_init = init;
        changed_init.back() ^= 0x80;
        CHECK(first && !cookies.verify(
            *first, source, session_id, changed_init));

        // One previous secret remains valid across a rotation boundary.
        clock.advance(std::chrono::milliseconds(100));
        CHECK(first && cookies.verify(*first, source, session_id, init));
        const auto second = cookies.issue(source, session_id, init);
        CHECK(second.has_value());
        CHECK(first && second && *first != *second);

        // After the next rotation, the original secret is no longer retained.
        clock.advance(std::chrono::milliseconds(100));
        CHECK(first && !cookies.verify(*first, source, session_id, init));
        CHECK(second && cookies.verify(*second, source, session_id, init));
    }

    // ---- 11. Cookie issuance fails closed without secure randomness ---------
    {
        ManualClock clock;
        FailingRandom random;
        HandshakeCookieManager cookies(clock, random);
        const Endpoint source = Endpoint::from_parts(127, 0, 0, 1, 5000);
        const std::array<uint8_t, 1> init{0x42};
        const HandshakeCookie forged{};
        CHECK(!cookies.issue(source, 1, init).has_value());
        CHECK(!cookies.verify(forged, source, 1, init));
    }

    printf("\n%d / %d passed\n", passed, tests);
    platform_cleanup_winsock();
    return (passed == tests) ? 0 : 1;
}
