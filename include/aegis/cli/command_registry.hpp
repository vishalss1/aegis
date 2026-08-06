#pragma once

#include "aegis/cli/cli_types.hpp"
#include <functional>
#include <map>
#include <string>
#include <vector>

using CommandHandler = std::function<int(const ParsedInput&, CliContext&)>;

struct CommandDef {
    std::string name;
    std::string description;
    CommandHandler handler;
};

class CommandRegistry {
public:
    void register_command(const std::string& name, const std::string& description, CommandHandler handler);
    bool dispatch(const ParsedInput& input, CliContext& ctx) const;
    void print_help() const;
    bool has_command(const std::string& name) const;

private:
    std::map<std::string, CommandDef> commands_;
};
