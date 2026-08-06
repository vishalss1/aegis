#pragma once

#include "aegis/config/config.hpp"
#include "aegis/identity/identity.hpp"
#include "aegis/tunnel/tunnel.hpp"
#include <memory>
#include <string>
#include <vector>

enum class InputMode { Command, Message };

struct ParsedInput {
    InputMode mode;
    std::string command;            // e.g. "config", "peers", "quit"
    std::vector<std::string> args;  // space-split, quote-aware
    std::string raw_text;           // original line for message mode
    bool is_bare_slash = false;     // true if input was bare '/'
};

enum class CliState { NoNetwork, Running };

struct CliContext {
    CliState state = CliState::NoNetwork;
    Identity identity;
    AppConfig active_config;
    std::unique_ptr<Tunnel> tunnel;
    bool quit_requested = false;
};
