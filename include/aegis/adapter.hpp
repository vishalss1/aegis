#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wintun.h>

class Adapter {
public:
    Adapter();
    ~Adapter();

    Adapter(const Adapter&) = delete;
    Adapter& operator=(const Adapter&) = delete;

    bool create();
    void close();

    bool read_packet(std::vector<uint8_t>& out, DWORD timeout_ms = 5000);
    bool write_packet(const std::vector<uint8_t>& data);

    uint32_t interface_index() const { return if_index_; }
    bool is_open() const { return adapter_ != nullptr; }

    static void print_packet(const uint8_t* data, size_t len);

private:
    bool load_wintun_dll();
    bool configure_ip();

    HMODULE wintun_dll_ = nullptr;

    WINTUN_CREATE_ADAPTER_FUNC*           WintunCreateAdapter_           = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC*            WintunCloseAdapter_            = nullptr;
    WINTUN_START_SESSION_FUNC*            WintunStartSession_            = nullptr;
    WINTUN_END_SESSION_FUNC*              WintunEndSession_              = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC*           WintunReceivePacket_           = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC*   WintunReleaseReceivePacket_    = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC*     WintunAllocateSendPacket_      = nullptr;
    WINTUN_SEND_PACKET_FUNC*              WintunSendPacket_              = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC*      WintunGetReadWaitEvent_        = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC*         WintunGetAdapterLUID_          = nullptr;
    WINTUN_SET_LOGGER_FUNC*               WintunSetLogger_               = nullptr;

    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    NET_IFINDEX if_index_ = 0;
};
