#include "aegis/cli/repl.hpp"
#include "aegis/cli/cli_types.hpp"
#include "aegis/cli/command_registry.hpp"
#include "aegis/cli/commands.hpp"
#include "aegis/cli/identity_store.hpp"
#include "aegis/cli/input_parser.hpp"
#include "aegis/cli/path_picker.hpp"
#include <iostream>
#include <string>

int run_repl() {
    CliContext ctx;
    NetworkId default_nid{};
    ctx.identity = load_or_create_identity(default_nid);

    CommandRegistry registry;
    register_cli_commands(registry);

    std::cout << "Aegis v0.1 — no active network yet. Type /config to create or join one, or /help.\n";

    std::string line_buffer;

    while (!ctx.quit_requested) {
        if (ctx.state == CliState::Running && ctx.tunnel && !ctx.active_config.iface.address.empty()) {
            std::string net_title = ctx.tunnel->network_name().empty() ? "Mesh" : ctx.tunnel->network_name();
            std::cout << "Aegis (" << net_title << ") [" << ctx.active_config.iface.address << "]> ";
        } else {
            std::cout << "> ";
        }
        std::fflush(stdout);

        std::string line;
        if (!std::getline(std::cin, line)) {
            // EOF reached
            break;
        }

        if (!line_buffer.empty()) {
            line = line_buffer + line;
            line_buffer.clear();
        }

        ParsedInput parsed = parse_cli_input(line);

        if (parsed.is_bare_slash) {
            std::string picked_path = run_path_picker();
            if (!picked_path.empty()) {
                line_buffer = picked_path + " ";
                std::cout << "Selected path inserted: " << picked_path << "\n";
            }
            continue;
        }

        if (parsed.mode == InputMode::Command) {
            if (!parsed.command.empty()) {
                registry.dispatch(parsed, ctx);
            }
        } else {
            // Message mode (non-slash input)
            if (!parsed.raw_text.empty()) {
                if (ctx.tunnel && ctx.state == CliState::Running) {
                    std::cout << "[You]: " << parsed.raw_text << "\n";
                    ctx.tunnel->broadcast_chat(parsed.raw_text);
                } else {
                    std::cout << "No active mesh network session. Type /config to create or join one first.\n";
                }
            }
        }
    }

    if (ctx.tunnel) {
        ctx.tunnel->stop();
        ctx.tunnel.reset();
    }

    return 0;
}
