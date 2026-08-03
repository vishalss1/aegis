#pragma once

#include "aegis/identity/identity.hpp"
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

// Config shape mirrors the reference in CLAUDE.md. `peer` is a list for mesh
// mode; each entry carries endpoint + public_key (the NodeID is derived from
// the public key — peers are never configured by raw NodeID) + allowed_ips.
struct PeerConfig {
    std::string endpoint;                  // "203.0.113.2:51821"
    Key public_key{};
    std::vector<std::string> allowed_ips;  // "10.20.0.0/24"
};

struct InterfaceConfig {
    std::string address;                   // "10.10.0.1/24"
    uint16_t listen_port = 0;
};

struct AppConfig {
    InterfaceConfig iface;                   // field name avoids the MSVC `interface` macro
    std::optional<NetworkId> network_id;   // absent -> all-zero default network
    std::vector<PeerConfig> peers;
};

class Config {
public:
    Config();

    bool load(const std::string& path);
    bool parse_yaml(const std::string& content);

    const AppConfig& get() const { return config_; }

private:
    AppConfig config_;
};
