#include "aegis/cli/commands.hpp"
#include "aegis/invite/invite.hpp"
#include "aegis/platform/platform.hpp"
#include "aegis/platform/logger.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

// Helper to convert raw bytes to hex string
static std::string to_hex(const uint8_t* data, size_t len) {
    std::string s;
    s.reserve(len * 2);
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        s.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
        s.push_back(hex_chars[data[i] & 0x0F]);
    }
    return s;
}

// "a.b.c.d" -> network-byte-order uint32
static bool parse_ipv4_local(const char* s, uint32_t& out) {
    uint8_t a, b, c, d;
    if (sscanf_s(s, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) return false;
    out = htonl((static_cast<uint32_t>(a) << 24) |
                (static_cast<uint32_t>(b) << 16) |
                (static_cast<uint32_t>(c) << 8)  |
                static_cast<uint32_t>(d));
    return true;
}

// "a.b.c.d/plen" -> network-byte-order prefix + prefix length
static bool parse_cidr_local(const char* s, uint32_t& prefix, uint8_t& plen) {
    char ip_part[32];
    unsigned plen_raw = 0;
    if (sscanf_s(s, "%31[^/]/%u", ip_part, (unsigned)sizeof(ip_part), &plen_raw) != 2 ||
        plen_raw > 32)
        return false;
    if (!parse_ipv4_local(ip_part, prefix)) return false;
    plen = (uint8_t)plen_raw;
    return true;
}

static void make_adapter_name_local(uint32_t local_ip, char* buf, size_t n) {
    uint32_t ip_host = ntohl(local_ip);
    snprintf(buf, n, "Aegis %u.%u.%u.%u",
             (ip_host >> 24) & 0xFF, (ip_host >> 16) & 0xFF,
             (ip_host >>  8) & 0xFF,  ip_host        & 0xFF);
}

// Command: /help
static int cmd_help(const ParsedInput& input, CliContext& ctx) {
    (void)input;
    (void)ctx;
    std::printf("Aegis Interactive CLI Commands:\n\n");
    std::printf("  /help                     List available commands\n");
    std::printf("  /config                   Create or join a mesh network interactively\n");
    std::printf("  /config export [path]     Export current running config as YAML\n");
    std::printf("  /invite                   Generate invite code for current network\n");
    std::printf("  /connect <invite>         Connect to a peer using an invite code\n");
    std::printf("  /peers                    List known peers and connection health\n");
    std::printf("  /status                   Display node status and network details\n");
    std::printf("  /identity [--reveal]      Display local NodeID, Public Key, (and Private Key)\n");
    std::printf("  /quit or /exit            Clean shutdown of Aegis session\n");
    std::printf("  /                         Inline path picker\n\n");
    return 0;
}

// Helper to start tunnel from TunnelConfig
static bool start_tunnel_helper(CliContext& ctx, const TunnelConfig& tcfg) {
    if (!platform_is_admin()) {
        std::printf("Administrator privileges required to start virtual network adapter.\n");
        if (platform_elevate()) {
            std::printf("Relaunching elevated...\n");
            ctx.quit_requested = true;
            return true;
        }
        std::printf("Error: Elevation failed or cancelled.\n");
        return false;
    }

    char adapter_name[64];
    make_adapter_name_local(tcfg.local_ip, adapter_name, sizeof(adapter_name));

    ctx.tunnel = std::make_unique<Tunnel>();
    if (!ctx.tunnel->start(tcfg, adapter_name)) {
        std::printf("Error: Failed to start Aegis tunnel.\n");
        ctx.tunnel.reset();
        return false;
    }

    ctx.state = CliState::Running;
    std::printf("Tunnel started successfully on interface %s.\n", adapter_name);
    return true;
}

// Command: /config
static int cmd_config(const ParsedInput& input, CliContext& ctx) {
    if (!input.args.empty() && input.args[0] == "export") {
        std::string yaml;
        yaml += "interface:\n";
        yaml += "  address: " + (ctx.active_config.iface.address.empty() ? "10.10.0.1/24" : ctx.active_config.iface.address) + "\n";
        yaml += "  listen_port: " + std::to_string(ctx.active_config.iface.listen_port ? ctx.active_config.iface.listen_port : 51820) + "\n";
        if (ctx.active_config.iface.stun_server) {
            yaml += "  stun_server: " + *ctx.active_config.iface.stun_server + "\n";
        }
        yaml += "\nidentity:\n";
        yaml += "  network_id: " + to_hex(ctx.identity.network_id.data(), ctx.identity.network_id.size()) + "\n";
        if (ctx.active_config.invite) {
            yaml += "  invite: " + *ctx.active_config.invite + "\n";
        }

        if (!ctx.active_config.peers.empty()) {
            yaml += "\npeer:\n";
            for (const auto& p : ctx.active_config.peers) {
                yaml += "  - endpoint: " + p.endpoint + "\n";
                yaml += "    public_key: " + to_hex(p.public_key.data(), p.public_key.size()) + "\n";
                yaml += "    allowed_ips:\n";
                for (const auto& ip : p.allowed_ips) {
                    yaml += "      - " + ip + "\n";
                }
            }
        }

        if (input.args.size() >= 2) {
            std::string path = input.args[1];
            std::ofstream out(path);
            if (out.is_open()) {
                out << yaml;
                std::printf("Configuration exported to %s\n", path.c_str());
            } else {
                std::printf("Error: Failed to write to file %s\n", path.c_str());
            }
        } else {
            std::cout << yaml;
        }
        return 0;
    }

    std::printf("\n--- Aegis Zero-Config Setup ---\n");
    std::printf("1. Create a new mesh network\n");
    std::printf("2. Join an existing mesh network with an invite code\n");
    std::printf("Choose option (1-2): ");
    std::fflush(stdout);

    std::string choice;
    if (!std::getline(std::cin, choice) || choice.empty()) {
        std::printf("Setup cancelled.\n");
        return 0;
    }

    if (choice == "1") {
        std::printf("\n[Creating New Mesh]\n");
        std::string addr = "10.10.0.1/24";
        std::printf("Overlay address [%s]: ", addr.c_str());
        std::fflush(stdout);
        std::string input_addr;
        if (std::getline(std::cin, input_addr) && !input_addr.empty()) {
            addr = input_addr;
        }

        uint16_t port = 51820;
        std::printf("Listen port [%u]: ", port);
        std::fflush(stdout);
        std::string input_port;
        if (std::getline(std::cin, input_port) && !input_port.empty()) {
            port = (uint16_t)std::atoi(input_port.c_str());
        }

        // Generate network identity
        NetworkId nid{};
        for (size_t i = 0; i < nid.size(); ++i) nid[i] = (uint8_t)(rand() % 256);
        ctx.identity.network_id = nid;

        TunnelConfig tcfg;
        tcfg.identity = ctx.identity;
        if (!parse_cidr_local(addr.c_str(), tcfg.local_ip, tcfg.local_prefix)) {
            std::printf("Error: Invalid CIDR format %s\n", addr.c_str());
            return 1;
        }
        tcfg.listen_port = port;

        ctx.active_config.iface.address = addr;
        ctx.active_config.iface.listen_port = port;
        ctx.active_config.network_id = nid;

        std::printf("\nGenerated NetworkID: %s\n", to_hex(nid.data(), nid.size()).c_str());
        std::printf("NodeID:              %s\n", to_hex(ctx.identity.node_id.data(), ctx.identity.node_id.size()).c_str());

        return start_tunnel_helper(ctx, tcfg) ? 0 : 1;
    } else if (choice == "2") {
        std::printf("\n[Joining Mesh]\n");
        std::printf("Paste AEGIS1 invite code: ");
        std::fflush(stdout);
        std::string invite_str;
        if (!std::getline(std::cin, invite_str) || invite_str.empty()) {
            std::printf("Cancelled.\n");
            return 0;
        }

        auto inv = decode_invite(invite_str);
        if (!inv) {
            std::printf("Error: Invalid AEGIS1 invite code.\n");
            return 1;
        }

        std::string addr = "10.10.0.2/24";
        std::printf("Overlay address [%s]: ", addr.c_str());
        std::fflush(stdout);
        std::string input_addr;
        if (std::getline(std::cin, input_addr) && !input_addr.empty()) {
            addr = input_addr;
        }

        uint16_t port = 51821;
        std::printf("Listen port [%u]: ", port);
        std::fflush(stdout);
        std::string input_port;
        if (std::getline(std::cin, input_port) && !input_port.empty()) {
            port = (uint16_t)std::atoi(input_port.c_str());
        }

        if (ctx.identity.keypair.public_key == inv->bootstrap_pubkey) {
            std::printf("\nNote: Same-machine testing detected (local key matches bootstrap key).\n");
            std::printf("Generating a fresh identity for this node...\n");
            ctx.identity = Identity::create(inv->network_id);
        } else {
            ctx.identity.network_id = inv->network_id;
        }

        TunnelConfig tcfg;
        tcfg.identity = ctx.identity;
        if (!parse_cidr_local(addr.c_str(), tcfg.local_ip, tcfg.local_prefix)) {
            std::printf("Error: Invalid CIDR format %s\n", addr.c_str());
            return 1;
        }
        tcfg.listen_port = port;

        TunnelPeer tp;
        tp.node_id = hash_public_key(inv->bootstrap_pubkey);
        tp.public_key = inv->bootstrap_pubkey;
        tp.endpoint = inv->bootstrap_endpoint;
        AllowedIP aip;
        aip.prefix = inv->bootstrap_prefix;
        aip.prefix_length = inv->bootstrap_prefix_len;
        tp.allowed_ips.push_back(aip);
        tcfg.peers.push_back(tp);

        ctx.active_config.iface.address = addr;
        ctx.active_config.iface.listen_port = port;
        ctx.active_config.network_id = inv->network_id;
        ctx.active_config.invite = invite_str;

        std::printf("Invite decoded successfully. Bootstrap peer: %s\n", to_hex(tp.node_id.data(), tp.node_id.size()).c_str());

        return start_tunnel_helper(ctx, tcfg) ? 0 : 1;
    } else {
        std::printf("Invalid option.\n");
        return 0;
    }
}

// Command: /invite
static int cmd_invite(const ParsedInput& input, CliContext& ctx) {
    (void)input;
    if (ctx.state != CliState::Running || !ctx.tunnel) {
        std::printf("No active network. Start a network with /config first.\n");
        return 0;
    }

    InvitePayload p;
    p.network_id = ctx.identity.network_id;
    p.bootstrap_pubkey = ctx.identity.keypair.public_key;

    // Use STUN endpoint or local IP & listen port
    if (auto stun_ep = ctx.tunnel->stun_public_endpoint()) {
        p.bootstrap_endpoint = *stun_ep;
    } else {
        uint32_t loopback_ip = htonl((127 << 24) | 1);
        p.bootstrap_endpoint = Endpoint{loopback_ip, htons(ctx.active_config.iface.listen_port)};
    }

    uint32_t local_ip = 0;
    uint8_t plen = 0;
    parse_cidr_local(ctx.active_config.iface.address.c_str(), local_ip, plen);
    p.bootstrap_prefix = local_ip;
    p.bootstrap_prefix_len = plen;

    std::string invite_code = encode_invite(p);
    std::printf("\nAEGIS Invite Code for current network:\n%s\n\n", invite_code.c_str());
    return 0;
}

// Command: /connect
static int cmd_connect(const ParsedInput& input, CliContext& ctx) {
    if (input.args.empty()) {
        std::printf("Usage: /connect <invite_code>\n");
        return 0;
    }

    if (ctx.state != CliState::Running || !ctx.tunnel) {
        std::printf("No active network running. Run /config first.\n");
        return 0;
    }

    std::string invite_str = input.args[0];
    auto inv = decode_invite(invite_str);
    if (!inv) {
        std::printf("Error: Invalid invite code format.\n");
        return 1;
    }

    if (!ctx.identity.matches_network(inv->network_id)) {
        std::printf("Error: Invite code is for a different NetworkID.\n");
        return 1;
    }

    TunnelPeer tp;
    tp.node_id = hash_public_key(inv->bootstrap_pubkey);
    tp.public_key = inv->bootstrap_pubkey;
    tp.endpoint = inv->bootstrap_endpoint;
    AllowedIP aip;
    aip.prefix = inv->bootstrap_prefix;
    aip.prefix_length = inv->bootstrap_prefix_len;
    tp.allowed_ips.push_back(aip);

    ctx.tunnel->peers().upsert(tp.node_id, tp.public_key, tp.endpoint, true);
    std::printf("Connecting to peer %s...\n", to_hex(tp.node_id.data(), tp.node_id.size()).c_str());
    return 0;
}

// Command: /peers
static int cmd_peers(const ParsedInput& input, CliContext& ctx) {
    (void)input;
    if (ctx.state != CliState::Running || !ctx.tunnel) {
        std::printf("No active network.\n");
        return 0;
    }

    auto peers = ctx.tunnel->peers().all_peers();
    std::printf("\nKnown Peers (%zu total):\n", peers.size());
    std::printf("%-16s %-12s %-22s %-8s\n", "NodeID (prefix)", "State", "Endpoint", "Type");
    std::printf("------------------------------------------------------------\n");
    for (const auto* p : peers) {
        std::string nid_str = to_hex(p->node_id.data(), 8) + "...";
        std::string state_str = "Unknown";
        switch (p->state) {
            case PeerState::Discovering: state_str = "Discovering"; break;
            case PeerState::Connecting:  state_str = "Connecting"; break;
            case PeerState::Established: state_str = "Established"; break;
            case PeerState::Dead:        state_str = "Dead"; break;
            default: break;
        }
        std::string ep_str = "N/A";
        if (p->endpoint) {
            uint32_t ip_h = ntohl(p->endpoint->ip);
            uint16_t port_h = ntohs(p->endpoint->port);
            char buf[32];
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                     (ip_h >> 24) & 0xFF, (ip_h >> 16) & 0xFF,
                     (ip_h >> 8) & 0xFF, ip_h & 0xFF, port_h);
            ep_str = buf;
        }
        std::printf("%-16s %-12s %-22s %-8s\n",
                    nid_str.c_str(), state_str.c_str(), ep_str.c_str(),
                    p->trusted ? "Trusted" : "Gossiped");
    }
    std::printf("\n");
    return 0;
}

// Command: /status
static int cmd_status(const ParsedInput& input, CliContext& ctx) {
    (void)input;
    std::printf("\n--- Aegis Node Status ---\n");
    std::printf("Status:      %s\n", ctx.state == CliState::Running ? "RUNNING" : "NO ACTIVE NETWORK");
    std::printf("NodeID:      %s\n", to_hex(ctx.identity.node_id.data(), ctx.identity.node_id.size()).c_str());
    std::printf("NetworkID:   %s\n", to_hex(ctx.identity.network_id.data(), ctx.identity.network_id.size()).c_str());

    if (ctx.state == CliState::Running && ctx.tunnel) {
        std::printf("Overlay IP:  %s\n", ctx.active_config.iface.address.c_str());
        std::printf("Listen Port: %u\n", ctx.active_config.iface.listen_port);
        std::printf("Peers:       %zu active\n", ctx.tunnel->peers().size());
    }
    std::printf("\n");
    return 0;
}

// Command: /identity
static int cmd_identity(const ParsedInput& input, CliContext& ctx) {
    bool reveal = !input.args.empty() && input.args[0] == "--reveal";

    std::printf("\n--- Local Node Identity ---\n");
    std::printf("NodeID:     %s\n", to_hex(ctx.identity.node_id.data(), ctx.identity.node_id.size()).c_str());
    std::printf("Public Key: %s\n", to_hex(ctx.identity.keypair.public_key.data(), ctx.identity.keypair.public_key.size()).c_str());
    std::printf("NetworkID:  %s\n", to_hex(ctx.identity.network_id.data(), ctx.identity.network_id.size()).c_str());
    if (reveal) {
        std::printf("Private Key: %s [REVEALED]\n", to_hex(ctx.identity.keypair.private_key.data(), ctx.identity.keypair.private_key.size()).c_str());
    } else {
        std::printf("Private Key: [PROTECTED - use /identity --reveal to show]\n");
    }
    std::printf("\n");
    return 0;
}

// Command: /verbose [on|off]
static int cmd_verbose(const ParsedInput& input, CliContext& ctx) {
    (void)ctx;
    if (input.args.empty()) {
        std::printf("Verbose debug logging is currently %s.\nUsage: /verbose <on|off>\n",
                    is_verbose_logging_enabled() ? "ON" : "OFF");
        return 0;
    }
    std::string arg = input.args[0];
    if (arg == "on" || arg == "true" || arg == "1") {
        set_verbose_logging(true);
        std::printf("Verbose debug logging enabled.\n");
    } else if (arg == "off" || arg == "false" || arg == "0") {
        set_verbose_logging(false);
        std::printf("Verbose debug logging disabled.\n");
    } else {
        std::printf("Usage: /verbose <on|off>\n");
    }
    return 0;
}

// Command: /quit or /exit
static int cmd_quit(const ParsedInput& input, CliContext& ctx) {
    (void)input;
    std::printf("Shutting down Aegis session...\n");
    if (ctx.tunnel) {
        ctx.tunnel->stop();
        ctx.tunnel.reset();
    }
    ctx.state = CliState::NoNetwork;
    ctx.quit_requested = true;
    return 0;
}

void register_cli_commands(CommandRegistry& registry) {
    registry.register_command("help", "List commands", cmd_help);
    registry.register_command("config", "Interactive create-or-join flow / export config", cmd_config);
    registry.register_command("invite", "Generate an invite code for the current network", cmd_invite);
    registry.register_command("connect", "Connect to a peer via invite code", cmd_connect);
    registry.register_command("peers", "List known peers and health state", cmd_peers);
    registry.register_command("status", "Show current node status and active sessions", cmd_status);
    registry.register_command("identity", "Show local NodeID and public key", cmd_identity);
    registry.register_command("verbose", "Toggle background debug logging (on/off)", cmd_verbose);
    registry.register_command("quit", "Clean shutdown", cmd_quit);
    registry.register_command("exit", "Clean shutdown", cmd_quit);
}
