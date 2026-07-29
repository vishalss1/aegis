#pragma once

#include "identity.hpp"
#include <cstdint>
#include <string>
#include <optional>
#include <vector>

struct PeerConfig {
    std::string endpoint;
    uint16_t port;
    Key public_key;
    std::string allowed_ips;
};

struct InterfaceConfig {
    std::string address;
    uint16_t listen_port;
};

struct AppConfig {
    InterfaceConfig interface;
    NetworkId network_id;
    std::vector<PeerConfig> peers;
    std::string identity_path;
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
