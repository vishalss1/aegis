#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct WintunAdapter;

class Adapter {
public:
    Adapter();
    ~Adapter();

    bool create(const std::wstring& pool, const std::wstring& name);
    void close();

    bool read_packet(std::vector<uint8_t>& out);
    bool write_packet(const std::vector<uint8_t>& data);

    uint32_t interface_index() const;

private:
    WintunAdapter* adapter_ = nullptr;
    void* session_ = nullptr;
};
