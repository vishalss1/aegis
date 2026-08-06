#include "aegis/platform/logger.hpp"
#include <cstdarg>
#include <cstdio>

bool g_verbose_logging = false;

void set_verbose_logging(bool enable) {
    g_verbose_logging = enable;
}

bool is_verbose_logging_enabled() {
    return g_verbose_logging;
}

void aegis_log(const char* fmt, ...) {
    if (!g_verbose_logging) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}
