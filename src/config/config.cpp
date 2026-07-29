#include "aegis/config.hpp"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <cstring>

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

bool Config::parse_yaml(const std::string& content) {
    (void)content;
    fprintf(stderr, "[config] parse_yaml: not implemented\n");
    return false;
}
