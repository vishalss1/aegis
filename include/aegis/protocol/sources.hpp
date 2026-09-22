#pragma once

#include <chrono>

class ProtocolClock {
public:
    using time_point = std::chrono::steady_clock::time_point;
    virtual ~ProtocolClock() = default;
    [[nodiscard]] virtual time_point now() const noexcept = 0;
};

class SystemProtocolClock final : public ProtocolClock {
public:
    [[nodiscard]] time_point now() const noexcept override {
        return std::chrono::steady_clock::now();
    }
};

inline ProtocolClock& system_protocol_clock() {
    static SystemProtocolClock clock;
    return clock;
}
