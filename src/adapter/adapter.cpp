#include "aegis/adapter.hpp"
#include <cstdio>

Adapter::Adapter() = default;
Adapter::~Adapter() { close(); }

bool Adapter::create(const std::wstring& pool, const std::wstring& name) {
    fprintf(stderr, "[adapter] create: %S / %S\n", pool.c_str(), name.c_str());
    return false;
}

void Adapter::close() {}

bool Adapter::read_packet(std::vector<uint8_t>& out) {
    (void)out;
    return false;
}

bool Adapter::write_packet(const std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

uint32_t Adapter::interface_index() const { return 0; }
