#pragma once

#include "aegis/identity/identity.hpp"
#include <string>

std::string get_identity_file_path();
Identity load_or_create_identity(const NetworkId& network_id, const std::string& custom_path = "");
