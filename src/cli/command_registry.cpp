#include "aegis/cli/command_registry.hpp"
#include <cstdio>
#include <iomanip>
#include <iostream>

void CommandRegistry::register_command(const std::string& name, const std::string& description, CommandHandler handler) {
    commands_[name] = CommandDef{name, description, handler};
}

bool CommandRegistry::has_command(const std::string& name) const {
    return commands_.find(name) != commands_.end();
}

bool CommandRegistry::dispatch(const ParsedInput& input, CliContext& ctx) const {
    if (input.mode != InputMode::Command) {
        return false;
    }

    auto it = commands_.find(input.command);
    if (it == commands_.end()) {
        std::printf("unknown command '/%s' — /help for a list\n", input.command.c_str());
        return false;
    }

    it->second.handler(input, ctx);
    return true;
}

void CommandRegistry::print_help() const {
    std::printf("Available slash commands:\n\n");
    for (const auto& [name, def] : commands_) {
        std::printf("  /%-20s %s\n", name.c_str(), def.description.c_str());
    }
    std::printf("\nType / to open the inline path picker.\n");
}
