#include "aegis/config/config.hpp"
#include <cstdio>
#include <cstring>
#include <string>

static int tests  = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool _ok = !!(cond); \
    passed += _ok; \
    printf("  %s: %s\n", _ok ? "PASS" : "FAIL", #cond); \
} while(0)

static const char* SAMPLE = R"(
# aegis node config
interface:
  address: 10.10.0.1/24
  listen_port: 51820

identity:
  network_id: 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

peer:
  - endpoint: 203.0.113.2:51821
    public_key: 0000000000000000000000000000000000000000000000000000000000000001
    allowed_ips:
      - 10.20.0.0/24
      - 10.20.1.0/24
  - endpoint: 198.51.100.7:51822
    public_key: 0000000000000000000000000000000000000000000000000000000000000002
    allowed_ips:
      - 10.20.2.0/24
)";

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- config tests ---\n");

    // ---- 1. Full sample parse ----------------------------------------------
    {
        Config cfg;
        CHECK(cfg.parse_yaml(SAMPLE));
        const AppConfig& app = cfg.get();
        CHECK(app.iface.address == "10.10.0.1/24");
        CHECK(app.iface.listen_port == 51820);
        CHECK(app.network_id.has_value());
        CHECK(app.network_id->size() == 32);
        CHECK((*app.network_id)[0] == 0x00 && (*app.network_id)[1] == 0x01);
        CHECK((*app.network_id)[31] == 0x0f);
        CHECK(app.peers.size() == 2);

        CHECK(app.peers[0].endpoint == "203.0.113.2:51821");
        CHECK(app.peers[0].public_key[31] == 0x01);
        CHECK(app.peers[0].allowed_ips.size() == 2);
        CHECK(app.peers[0].allowed_ips[0] == "10.20.0.0/24");
        CHECK(app.peers[0].allowed_ips[1] == "10.20.1.0/24");

        CHECK(app.peers[1].endpoint == "198.51.100.7:51822");
        CHECK(app.peers[1].public_key[31] == 0x02);
        CHECK(app.peers[1].allowed_ips.size() == 1);
        CHECK(app.peers[1].allowed_ips[0] == "10.20.2.0/24");
    }

    // ---- 2. Inline first key on a list item ---------------------------------
    {
        Config cfg;
        bool ok = cfg.parse_yaml(
            "interface:\n"
            "  address: 10.0.0.1/24\n"
            "  listen_port: 51999\n"
            "peer:\n"
            "  - endpoint: 203.0.113.9:12345\n"
            "    public_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "    allowed_ips:\n"
            "      - 10.9.0.0/16\n");
        CHECK(ok);
        CHECK(cfg.get().peers.size() == 1);
        CHECK(cfg.get().peers[0].endpoint == "203.0.113.9:12345");
        CHECK(cfg.get().peers[0].public_key[0] == 0xaa);
    }

    // ---- 3. Missing identity / peer are optional ----------------------------
    {
        Config cfg;
        CHECK(cfg.parse_yaml(
            "interface:\n"
            "  address: 10.0.0.1/24\n"
            "  listen_port: 51820\n"));
        CHECK(!cfg.get().network_id.has_value());
        CHECK(cfg.get().peers.empty());
    }

    // ---- 4. Errors ----------------------------------------------------------
    {
        Config cfg;
        CHECK(!cfg.parse_yaml("interface:\n  listen_port: 51820\n"));        // no address
        CHECK(!cfg.parse_yaml("interface:\n  address: 10.0.0.1/24\n"));      // no port
        CHECK(!cfg.parse_yaml("interface:\n  address: 10.0.0.1/24\n  listen_port: 0\n"));  // port 0
        CHECK(!cfg.parse_yaml("interface:\n  address: 10.0.0.1/24\n  listen_port: 70000\n"));  // port range
        CHECK(!cfg.parse_yaml("foo:\n  bar: 1\n"));                          // unknown top-level
        CHECK(!cfg.parse_yaml("interface:\n  bogus: 1\n"));                  // unknown key
        CHECK(!cfg.parse_yaml(
            "interface:\n  address: 10.0.0.1/24\n  listen_port: 51820\n"
            "peer:\n  - endpoint: 203.0.113.2:51821\n    public_key: xyz\n"));  // bad hex
        CHECK(!cfg.parse_yaml(
            "interface:\n  address: 10.0.0.1/24\n  listen_port: 51820\n"
            "peer:\n  - endpoint: 203.0.113.2:51821\n    public_key: 00\n"));   // short key
        CHECK(!cfg.parse_yaml("interface:\n  address: 10.0.0.1/24\n  listen_port: 51820\n  peer:\n"));  // peer under interface
        CHECK(!cfg.parse_yaml(
            "interface:\n  address: 10.0.0.1/24\n  listen_port: 51820\n"
            "peer:\n  - endpoint: 203.0.113.2:51821\n"));                       // no public_key
    }

    // ---- 5. Re-parse resets previous state ----------------------------------
    {
        Config cfg;
        CHECK(cfg.parse_yaml(SAMPLE));
        CHECK(cfg.parse_yaml(
            "interface:\n  address: 10.0.0.1/24\n  listen_port: 51820\n"));
        CHECK(cfg.get().peers.empty());
        CHECK(!cfg.get().network_id.has_value());
    }

    printf("\n%d / %d passed\n", passed, tests);
    return (passed == tests) ? 0 : 1;
}
