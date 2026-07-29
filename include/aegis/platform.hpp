#pragma once

#include <cstdint>
#include <string>
#include <vector>

bool platform_init_winsock();
void platform_cleanup_winsock();

bool platform_is_admin();
bool platform_elevate();

std::string platform_error_string(int error_code);
int platform_last_error();
