#include "aegis/platform/platform.hpp"
#include <winsock2.h>
#include <windows.h>
#include <cstdio>

bool platform_init_winsock() {
    WSADATA wsa;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        fprintf(stderr, "[platform] WSAStartup: error %d\n", ret);
        return false;
    }
    return true;
}

void platform_cleanup_winsock() {
    WSACleanup();
}

bool platform_is_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&nt_auth, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &admin_group)) {
        if (!CheckTokenMembership(nullptr, admin_group, &is_admin))
            is_admin = FALSE;
        FreeSid(admin_group);
    }
    return is_admin != FALSE;
}

bool platform_elevate() {
    fprintf(stderr, "[platform] elevate: not implemented\n");
    return false;
}

std::string platform_error_string(int error_code) {
    char buf[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, (DWORD)error_code,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, sizeof(buf), nullptr);
    return buf;
}

int platform_last_error() {
    return (int)WSAGetLastError();
}
