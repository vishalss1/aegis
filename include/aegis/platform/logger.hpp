#pragma once

#include <cstdio>

extern bool g_verbose_logging;

void set_verbose_logging(bool enable);
bool is_verbose_logging_enabled();

void aegis_log(const char* fmt, ...);
