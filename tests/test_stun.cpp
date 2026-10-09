#include "aegis/stun/stun.hpp"
#include "aegis/platform/platform.hpp"
#include <cstdio>
#include <mutex>

class FixedRandom final : public RandomSource {
public:
    [[nodiscard]] bool fill(std::span<uint8_t> output) override {
        for (size_t i = 0; i < output.size(); ++i)
            output[i] = static_cast<uint8_t>(i + 1);
        return true;
    }
};

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
    printf("--- STUN RFC 5389 tests ---\n");

    platform_init_winsock();

    uint8_t tx_id[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    auto req = create_stun_binding_request(tx_id);

    CHECK(req.size() == 20);
    CHECK(req[0] == 0x00 && req[1] == 0x01); // Binding request
    CHECK(req[4] == 0x21 && req[5] == 0x12 && req[6] == 0xA4 && req[7] == 0x42); // Magic cookie

    // Synthesize a valid STUN Binding Response
    // Header (20 bytes): type=0x0101, len=12 (0x000c), cookie=0x2112A442, tx_id
    // Attribute XOR-MAPPED-ADDRESS: type=0x0020, len=8, reserved=0, family=1, xor_port, xor_ip
    std::vector<uint8_t> resp = {
        0x01, 0x01, 0x00, 0x0C,
        0x21, 0x12, 0xA4, 0x42,
        1,2,3,4,5,6,7,8,9,10,11,12,
        // Attr header
        0x00, 0x20, 0x00, 0x08,
        0x00, 0x01
    };

    // XOR 192.168.1.50 (0xC0A80132) with 0x2112A442 = 0xE1BAA570
    // XOR port 51820 (0xCA6C) with 0x2112 = 0xEB7E
    uint16_t xor_port = 0xEB7E;
    uint32_t xor_ip = 0xE1BAA570;

    resp.push_back((uint8_t)(xor_port >> 8));
    resp.push_back((uint8_t)(xor_port & 0xFF));

    resp.push_back((uint8_t)(xor_ip >> 24));
    resp.push_back((uint8_t)(xor_ip >> 16));
    resp.push_back((uint8_t)(xor_ip >> 8));
    resp.push_back((uint8_t)(xor_ip & 0xFF));

    auto parsed = parse_stun_binding_response(resp.data(), resp.size(), tx_id);
    CHECK(parsed.has_value());
    if (parsed) {
        CHECK(ntohs(parsed->port) == 51820);
        uint32_t ip_host = ntohl(parsed->ipv4_network());
        CHECK(ip_host == 0xC0A80132); // 192.168.1.50
    }

    // Exact declared length and complete attribute validation are required.
    {
        auto trailing = resp;
        trailing.push_back(0);
        CHECK(!parse_stun_binding_response(
            trailing.data(), trailing.size(), tx_id).has_value());

        auto truncated = resp;
        truncated.pop_back();
        CHECK(!parse_stun_binding_response(
            truncated.data(), truncated.size(), tx_id).has_value());

        auto bad_declared_length = resp;
        bad_declared_length[3] = 0x08;
        CHECK(!parse_stun_binding_response(
            bad_declared_length.data(), bad_declared_length.size(), tx_id).has_value());

        auto malformed_after_valid = resp;
        malformed_after_valid[3] = 0x10;
        malformed_after_valid.insert(
            malformed_after_valid.end(), {0x00, 0x01, 0x00, 0x08});
        CHECK(!parse_stun_binding_response(
            malformed_after_valid.data(), malformed_after_valid.size(), tx_id).has_value());

        uint8_t wrong_tx_id[12] = {};
        CHECK(!parse_stun_binding_response(
            resp.data(), resp.size(), wrong_tx_id).has_value());
    }

    // Discovery must use the already-bound mesh socket so the mapped port is
    // meaningful for subsequent peer traffic.
    {
        constexpr uint16_t client_port = 7110;
        constexpr uint16_t server_port = 7111;
        constexpr uint16_t mapped_port = 62000;
        constexpr uint32_t mapped_ip = 0xCB00714Du; // 203.0.113.77
        Transport client;
        Transport server;
        CHECK(client.bind(client_port));
        CHECK(server.bind(server_port));

        bool request_valid = false;
        Endpoint observed_source{};
        std::mutex observation_mutex;
        CHECK(server.start_receive(
            [&](const uint8_t* data, size_t len, Endpoint sender) {
                if (len != 20 || data[0] != 0 || data[1] != 1)
                    return;
                std::vector<uint8_t> response = {
                    0x01, 0x01, 0x00, 0x0C,
                    0x21, 0x12, 0xA4, 0x42
                };
                response.insert(response.end(), data + 8, data + 20);
                response.insert(response.end(), {
                    0x00, 0x20, 0x00, 0x08, 0x00, 0x01
                });
                const uint16_t encoded_port = static_cast<uint16_t>(
                    mapped_port ^ 0x2112u);
                const uint32_t encoded_ip = mapped_ip ^ 0x2112A442u;
                response.push_back(static_cast<uint8_t>(encoded_port >> 8));
                response.push_back(static_cast<uint8_t>(encoded_port));
                response.push_back(static_cast<uint8_t>(encoded_ip >> 24));
                response.push_back(static_cast<uint8_t>(encoded_ip >> 16));
                response.push_back(static_cast<uint8_t>(encoded_ip >> 8));
                response.push_back(static_cast<uint8_t>(encoded_ip));
                {
                    std::lock_guard<std::mutex> lock(observation_mutex);
                    request_valid = true;
                    observed_source = sender;
                }
                (void)server.send(
                    response.data(), response.size(), sender,
                    SendPriority::Control);
            }));

        FixedRandom random;
        const auto discovered = stun_discover(
            client, "127.0.0.1", server_port, 2000, random);
        CHECK(discovered.has_value());
        CHECK(discovered && ntohl(discovered->ipv4_network()) == mapped_ip);
        CHECK(discovered && ntohs(discovered->port) == mapped_port);
        {
            std::lock_guard<std::mutex> lock(observation_mutex);
            CHECK(request_valid);
            CHECK(ntohs(observed_source.port) == client_port);
        }
        server.stop_receive();
        client.close();
        server.close();
    }

    // IPv6 XOR-MAPPED-ADDRESS is masked with the cookie and transaction ID.
    {
        // 2001:db8::1 port 40000
        const std::array<uint8_t, 16> address{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::vector<uint8_t> v6 = {
            0x01, 0x01, 0x00, 0x18,
            0x21, 0x12, 0xA4, 0x42,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            0x00, 0x20, 0x00, 0x14, 0x00, 0x02};
        const uint16_t encoded_port = static_cast<uint16_t>(40000u ^ 0x2112u);
        v6.push_back(static_cast<uint8_t>(encoded_port >> 8));
        v6.push_back(static_cast<uint8_t>(encoded_port));
        const uint8_t mask[16] = {0x21, 0x12, 0xA4, 0x42,
                                  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        for (size_t i = 0; i < 16; ++i)
            v6.push_back(static_cast<uint8_t>(address[i] ^ mask[i]));

        const auto parsed_v6 = parse_stun_binding_response(
            v6.data(), v6.size(), tx_id);
        CHECK(parsed_v6.has_value());
        CHECK(parsed_v6 && parsed_v6->is_ipv6());
        CHECK(parsed_v6 && parsed_v6->address.bytes == address);
        CHECK(parsed_v6 && ntohs(parsed_v6->port) == 40000);
        CHECK(parsed_v6 &&
              endpoint_to_string(*parsed_v6) == "[2001:db8::1]:40000");

        // A different transaction ID changes the mask, so a response bound
        // to another request cannot be replayed.
        uint8_t other_tx[12] = {12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
        CHECK(!parse_stun_binding_response(
            v6.data(), v6.size(), other_tx).has_value());

        auto short_v6 = v6;
        short_v6[3] = 0x14;
        short_v6[23] = 0x10;
        short_v6.resize(short_v6.size() - 4);
        CHECK(!parse_stun_binding_response(
            short_v6.data(), short_v6.size(), tx_id).has_value());
    }

    platform_cleanup_winsock();

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
