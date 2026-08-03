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
    wchar_t exe[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return false;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return false;

    std::wstring params;
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        bool need_quotes = arg.find(L' ') != std::wstring::npos;
        if (!params.empty()) params += L' ';
        if (need_quotes)
            params += L"\"" + arg + L"\"";
        else
            params += arg;
    }
    LocalFree(argv);

    // ShellExecuteW "runas" relaunches this process with the same arguments in
    // an elevated context (UAC prompt). The parent returns immediately; the
    // elevated child opens its own console.
    HINSTANCE h = ShellExecuteW(nullptr, L"runas", exe,
                                params.empty() ? nullptr : params.c_str(),
                                nullptr, SW_SHOWNORMAL);
    return (INT_PTR)h > 32;
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
