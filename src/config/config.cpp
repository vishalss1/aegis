#include "aegis/config/config.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

Config::Config() = default;

bool Config::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        fprintf(stderr, "[config] load: cannot open %s\n", path.c_str());
        return false;
    }
    std::stringstream ss;
    ss << file.rdbuf();
    return parse_yaml(ss.str());
}

namespace {

enum class Section { Root, Interface, Identity, Peers };

int yaml_indent(const std::string& line) {
    size_t i = 0;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i >= line.size() || line[i] == '#') return -1;
    return (int)i;
}

std::string yaml_trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
    while (b > a) {
        char c = s[b - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        b--;
    }
    return s.substr(a, b - a);
}

// Splits "key: value" at the first colon. Returns false if there is none.
bool yaml_split_key_value(const std::string& line, std::string& key, std::string& value) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return false;
    key = yaml_trim(line.substr(0, colon));
    value = yaml_trim(line.substr(colon + 1));
    return true;
}

bool parse_hex_bytes(const std::string& s, std::vector<uint8_t>& out) {
    if (s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto hexval = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

bool parse_network_id(const std::string& value, NetworkId& out) {
    std::vector<uint8_t> bytes;
    if (!parse_hex_bytes(value, bytes) || bytes.size() != NETWORK_ID_SIZE) return false;
    std::memcpy(out.data(), bytes.data(), NETWORK_ID_SIZE);
    return true;
}

bool parse_public_key(const std::string& value, Key& out) {
    std::vector<uint8_t> bytes;
    if (!parse_hex_bytes(value, bytes) || bytes.size() != KEY_SIZE) return false;
    std::memcpy(out.data(), bytes.data(), KEY_SIZE);
    return true;
}

bool parse_port(const std::string& value, uint16_t& out) {
    if (value.empty()) return false;
    for (char c : value)
        if (c < '0' || c > '9') return false;
    unsigned long v = std::strtoul(value.c_str(), nullptr, 10);
    if (v == 0 || v > 65535) return false;
    out = (uint16_t)v;
    return true;
}

}  // namespace

bool Config::parse_yaml(const std::string& content) {
    AppConfig cfg;
    Section section = Section::Root;
    bool in_peer_item = false;
    bool in_allowed = false;

    std::istringstream stream(content);
    std::string raw;
    while (std::getline(stream, raw)) {
        int indent = yaml_indent(raw);
        if (indent < 0) continue;
        std::string line = yaml_trim(raw);
        if (line.empty()) continue;

        if (indent == 0) {
            if (line == "interface:") {
                section = Section::Interface;
                in_peer_item = false;
                in_allowed = false;
                continue;
            }
            if (line == "identity:") {
                section = Section::Identity;
                in_peer_item = false;
                in_allowed = false;
                continue;
            }
            if (line == "peer:") {
                section = Section::Peers;
                in_peer_item = false;
                in_allowed = false;
                continue;
            }
            fprintf(stderr, "[config] parse_yaml: unexpected top-level key '%s'\n", line.c_str());
            return false;
        }

        if (section == Section::Interface) {
            std::string key, value;
            if (!yaml_split_key_value(line, key, value)) {
                fprintf(stderr, "[config] parse_yaml: bad interface line '%s'\n", line.c_str());
                return false;
            }
            if (key == "address") {
                if (value.empty()) return false;
                cfg.iface.address = value;
                continue;
            }
            if (key == "listen_port") {
                if (!parse_port(value, cfg.iface.listen_port)) return false;
                continue;
            }
            if (key == "stun_server") {
                if (value.empty()) return false;
                cfg.iface.stun_server = value;
                continue;
            }
            fprintf(stderr, "[config] parse_yaml: unknown interface key '%s'\n", key.c_str());
            return false;
        }

        if (section == Section::Identity) {
            std::string key, value;
            if (!yaml_split_key_value(line, key, value)) {
                fprintf(stderr, "[config] parse_yaml: bad identity line '%s'\n", line.c_str());
                return false;
            }
            if (key == "network_id") {
                NetworkId nid{};
                if (!parse_network_id(value, nid)) return false;
                cfg.network_id = nid;
                continue;
            }
            if (key == "invite") {
                if (value.empty()) return false;
                cfg.invite = value;
                continue;
            }
            fprintf(stderr, "[config] parse_yaml: unknown identity key '%s'\n", key.c_str());
            return false;
        }


        if (section == Section::Peers) {
            if (line.rfind("- ", 0) == 0) {
                std::string item = yaml_trim(line.substr(2));
                if (item.empty()) {
                    fprintf(stderr, "[config] parse_yaml: empty peer list item\n");
                    return false;
                }
                std::string key, value;
                if (yaml_split_key_value(item, key, value)) {
                    PeerConfig peer;
                    cfg.peers.push_back(std::move(peer));
                    in_peer_item = true;
                    in_allowed = false;
                    if (key == "endpoint") {
                        if (value.empty()) return false;
                        cfg.peers.back().endpoint = value;
                        continue;
                    }
                    if (key == "public_key") {
                        if (!parse_public_key(value, cfg.peers.back().public_key)) return false;
                        continue;
                    }
                    fprintf(stderr, "[config] parse_yaml: unknown peer key '%s'\n", key.c_str());
                    return false;
                }
                // A list item without a key is an allowed_ips entry.
                if (in_allowed && in_peer_item && !cfg.peers.empty()) {
                    cfg.peers.back().allowed_ips.push_back(item);
                    continue;
                }
                fprintf(stderr, "[config] parse_yaml: unexpected list item '%s'\n", item.c_str());
                return false;
            }

            if (!in_peer_item || cfg.peers.empty()) {
                fprintf(stderr, "[config] parse_yaml: peer key outside a list item '%s'\n", line.c_str());
                return false;
            }
            std::string key, value;
            if (!yaml_split_key_value(line, key, value)) {
                fprintf(stderr, "[config] parse_yaml: bad peer line '%s'\n", line.c_str());
                return false;
            }
            if (key == "endpoint") {
                if (value.empty()) return false;
                cfg.peers.back().endpoint = value;
                continue;
            }
            if (key == "public_key") {
                if (!parse_public_key(value, cfg.peers.back().public_key)) return false;
                continue;
            }
            if (key == "allowed_ips") {
                in_allowed = true;
                continue;
            }
            fprintf(stderr, "[config] parse_yaml: unknown peer key '%s'\n", key.c_str());
            return false;
        }

        fprintf(stderr, "[config] parse_yaml: content before any top-level section '%s'\n", line.c_str());
        return false;
    }

    if (cfg.iface.address.empty() || cfg.iface.listen_port == 0) {
        fprintf(stderr, "[config] parse_yaml: interface.address and listen_port are required\n");
        return false;
    }
    for (const auto& p : cfg.peers) {
        if (p.endpoint.empty()) {
            fprintf(stderr, "[config] parse_yaml: every peer needs an endpoint\n");
            return false;
        }
        if (p.public_key == Key{}) {
            fprintf(stderr, "[config] parse_yaml: every peer needs a public_key\n");
            return false;
        }
    }

    config_ = std::move(cfg);
    return true;
}
