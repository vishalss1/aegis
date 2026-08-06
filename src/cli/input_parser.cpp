#include "aegis/cli/input_parser.hpp"
#include <sstream>

ParsedInput parse_cli_input(const std::string& line) {
    ParsedInput result;
    result.raw_text = line;

    // Trim leading whitespace
    size_t start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        result.mode = InputMode::Message;
        return result;
    }

    std::string trimmed = line.substr(start);

    // Bare slash check
    if (trimmed == "/") {
        result.mode = InputMode::Command;
        result.is_bare_slash = true;
        return result;
    }

    // Slash command check
    if (trimmed[0] == '/') {
        result.mode = InputMode::Command;
        std::string cmd_str = trimmed.substr(1);

        // Parse command and space-separated / quote-aware arguments
        std::vector<std::string> tokens;
        std::string current_token;
        bool in_quotes = false;

        for (size_t i = 0; i < cmd_str.size(); ++i) {
            char c = cmd_str[i];
            if (c == '"') {
                in_quotes = !in_quotes;
            } else if ((c == ' ' || c == '\t') && !in_quotes) {
                if (!current_token.empty()) {
                    tokens.push_back(current_token);
                    current_token.clear();
                }
            } else {
                current_token.push_back(c);
            }
        }
        if (!current_token.empty()) {
            tokens.push_back(current_token);
        }

        if (!tokens.empty()) {
            result.command = tokens[0];
            for (size_t i = 1; i < tokens.size(); ++i) {
                result.args.push_back(tokens[i]);
            }
        }
        return result;
    }

    // Otherwise message mode
    result.mode = InputMode::Message;
    return result;
}
