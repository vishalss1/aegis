#include "aegis/discovery/discovery.hpp"
#include "aegis/identity/identity.hpp"
#include "aegis/platform/platform.hpp"
#include <chrono>
#include <cstdio>
#include <thread>

namespace {

constexpr uint16_t LIVE_DISCOVERY_PORT = DISCOVERY_PORT + 1;
constexpr auto DISCOVERY_DEADLINE = std::chrono::seconds(7);
constexpr auto POLL_INTERVAL = std::chrono::milliseconds(100);

}  // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (!platform_init_winsock()) {
        std::fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    NetworkId network{};
    network[0] = 0x01;
    Identity alice = Identity::create(network);
    Identity bob = Identity::create(network);

    const Endpoint alice_endpoint =
        Endpoint::from_parts(10, 10, 0, 1, 45120);
    const Endpoint bob_endpoint =
        Endpoint::from_parts(10, 10, 0, 2, 45121);

    Discovery alice_discovery;
    Discovery bob_discovery;
    const bool alice_started = alice_discovery.start(
        alice, alice_endpoint, LIVE_DISCOVERY_PORT);
    const bool bob_started = bob_discovery.start(
        bob, bob_endpoint, LIVE_DISCOVERY_PORT);

    bool alice_saw_bob = false;
    bool bob_saw_alice = false;
    if (alice_started && bob_started) {
        const auto deadline =
            std::chrono::steady_clock::now() + DISCOVERY_DEADLINE;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto alice_presences = alice_discovery.presences();
            const auto bob_presences = bob_discovery.presences();
            alice_saw_bob = alice_presences.contains(bob.node_id);
            bob_saw_alice = bob_presences.contains(alice.node_id);
            if (alice_saw_bob && bob_saw_alice)
                break;
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
    }

    alice_discovery.stop();
    bob_discovery.stop();
    platform_cleanup_winsock();

    if (!alice_started || !bob_started) {
        std::fprintf(stderr,
            "live discovery could not bind UDP port %u\n",
            LIVE_DISCOVERY_PORT);
        return 1;
    }
    if (!alice_saw_bob || !bob_saw_alice) {
        std::fprintf(stderr,
            "live discovery timed out (alice_saw_bob=%d, "
            "bob_saw_alice=%d)\n",
            alice_saw_bob ? 1 : 0, bob_saw_alice ? 1 : 0);
        return 1;
    }

    std::printf("live discovery broadcast passed on UDP port %u\n",
                LIVE_DISCOVERY_PORT);
    return 0;
}
