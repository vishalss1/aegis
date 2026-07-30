#include "aegis/adapter.hpp"

Adapter::Adapter() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

Adapter::~Adapter() { close(); }

static void CALLBACK wintun_log(_In_ WINTUN_LOGGER_LEVEL Level,
                                _In_ DWORD64 Timestamp,
                                _In_z_ LPCWSTR Message) {
    const char* level_str = "?";
    switch (Level) {
        case WINTUN_LOG_INFO: level_str = "INFO"; break;
        case WINTUN_LOG_WARN: level_str = "WARN"; break;
        case WINTUN_LOG_ERR:  level_str = "ERR";  break;
    }
    fprintf(stderr, "[wintun] %s: %ws\n", level_str, Message);
}

bool Adapter::load_wintun_dll() {
    wintun_dll_ = LoadLibraryExW(L"wintun.dll", nullptr,
                                 LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                 LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!wintun_dll_) {
        fprintf(stderr, "[adapter] LoadLibrary(wintun.dll) failed (error %lu)\n",
                GetLastError());
        return false;
    }
    fprintf(stderr, "[adapter] dll loaded\n");

#define LOAD_FN(name) do { \
    name##_ = (decltype(name##_))GetProcAddress(wintun_dll_, #name); \
    if (!name##_) { \
        fprintf(stderr, "[adapter] GetProcAddress(" #name ") failed\n"); \
        return false; \
    } } while(0)

    LOAD_FN(WintunCreateAdapter);
    LOAD_FN(WintunCloseAdapter);
    LOAD_FN(WintunStartSession);
    LOAD_FN(WintunEndSession);
    LOAD_FN(WintunReceivePacket);
    LOAD_FN(WintunReleaseReceivePacket);
    LOAD_FN(WintunAllocateSendPacket);
    LOAD_FN(WintunSendPacket);
    LOAD_FN(WintunGetReadWaitEvent);
    LOAD_FN(WintunGetAdapterLUID);
    LOAD_FN(WintunSetLogger);

#undef LOAD_FN
    fprintf(stderr, "[adapter] all procs loaded\n");
    return true;
}

bool Adapter::create() {
    fprintf(stderr, "[adapter] create: loading dll\n");
    if (!load_wintun_dll())
        return false;

    WintunSetLogger_(wintun_log);
    fprintf(stderr, "[adapter] logger set\n");

    fprintf(stderr, "[adapter] create: calling WintunCreateAdapter\n");
    adapter_ = WintunCreateAdapter_(L"Aegis Tunnel", L"Aegis", nullptr);
    if (!adapter_) {
        fprintf(stderr, "[adapter] WintunCreateAdapter failed (error %lu)\n",
                GetLastError());
        return false;
    }
    fprintf(stderr, "[adapter] adapter created\n");

    NET_LUID luid;
    WintunGetAdapterLUID_(adapter_, &luid);

    if (ConvertInterfaceLuidToIndex(&luid, &if_index_) != NO_ERROR) {
        fprintf(stderr, "[adapter] ConvertInterfaceLuidToIndex failed (error %lu)\n",
                GetLastError());
        WintunCloseAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    // Wait for the interface to be ready for IP config
    for (int i = 0; i < 50; i++) {
        ULONG bufLen = 0;
        GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufLen);
        std::vector<uint8_t> buf(bufLen);
        PIP_ADAPTER_ADDRESSES addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        ULONG ret = GetAdaptersAddresses(AF_INET, 0, nullptr, addrs, &bufLen);
        if (ret == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
                if (a->IfIndex == if_index_)
                    goto interface_ready;
            }
        }
        Sleep(100);
    }
    fprintf(stderr, "[adapter] interface not ready within 5s\n");
    WintunCloseAdapter_(adapter_);
    adapter_ = nullptr;
    return false;

interface_ready:
    // Configure IP BEFORE starting session (WireGuard example order)
    if (!configure_ip()) {
        close();
        return false;
    }

    // Use same ring capacity as WireGuard example
    session_ = WintunStartSession_(adapter_, 0x400000);
    if (!session_) {
        fprintf(stderr, "[adapter] WintunStartSession failed (error %lu)\n",
                GetLastError());
        WintunCloseAdapter_(adapter_);
        adapter_ = nullptr;
        return false;
    }

    fprintf(stderr, "[adapter] up  if_index=%lu  ip=10.10.0.1/24\n", if_index_);
    return true;
}

void Adapter::close() {
    if (session_) {
        WintunEndSession_(session_);
        session_ = nullptr;
    }
    if (adapter_) {
        WintunCloseAdapter_(adapter_);
        adapter_ = nullptr;
    }
    if (wintun_dll_) {
        FreeLibrary(wintun_dll_);
        wintun_dll_ = nullptr;
    }
    if_index_ = 0;
}

bool Adapter::configure_ip() {
    MIB_UNICASTIPADDRESS_ROW row = {};
    InitializeUnicastIpAddressEntry(&row);
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (10 << 16) | (0 << 8) | 1);
    row.OnLinkPrefixLength = 24;
    row.DadState = IpDadStatePreferred;
    row.InterfaceIndex = if_index_;

    ULONG ret = CreateUnicastIpAddressEntry(&row);
    if (ret == NO_ERROR) {
        fprintf(stderr, "[adapter] ip 10.10.0.1/24 configured\n");
        return true;
    }
    if (ret == ERROR_OBJECT_ALREADY_EXISTS) {
        fprintf(stderr, "[adapter] ip 10.10.0.1/24 already configured\n");
        return true;
    }
    fprintf(stderr, "[adapter] CreateUnicastIpAddressEntry failed (error %lu)\n", ret);
    return false;
}

bool Adapter::read_packet(std::vector<uint8_t>& out, DWORD timeout_ms) {
    if (!session_) return false;

    DWORD size = 0;
    BYTE* data = WintunReceivePacket_(session_, &size);
    if (!data) {
        DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            HANDLE ev = WintunGetReadWaitEvent_(session_);
            if (WaitForSingleObject(ev, timeout_ms) == WAIT_OBJECT_0)
                data = WintunReceivePacket_(session_, &size);
        }
        if (!data)
            return false;
    }

    out.assign(data, data + size);
    WintunReleaseReceivePacket_(session_, data);
    return true;
}

bool Adapter::write_packet(const std::vector<uint8_t>& data) {
    if (!session_) return false;

    BYTE* buf = WintunAllocateSendPacket_(session_, (DWORD)data.size());
    if (!buf) {
        fprintf(stderr, "[adapter] WintunAllocateSendPacket failed (error %lu)\n",
                GetLastError());
        return false;
    }

    std::memcpy(buf, data.data(), data.size());
    WintunSendPacket_(session_, buf);
    return true;
}

void Adapter::print_packet(const uint8_t* data, size_t len) {
    if (len < 20 || (data[0] >> 4) != 4) {
        printf("[pkt] non-IPv4 (ver=%u  len=%zu) | raw=",
               (len >= 1) ? (unsigned)(data[0] >> 4) : 0, len);
        size_t dump = (len > 64) ? 64 : len;
        for (size_t i = 0; i < dump; i++)
            printf("%02x", data[i]);
        putchar('\n');
        return;
    }

    uint8_t version_ihl = data[0];
    uint8_t proto        = data[9];
    uint32_t src = (uint32_t)data[12] << 24 | (uint32_t)data[13] << 16 |
                   (uint32_t)data[14] <<  8 | (uint32_t)data[15];
    uint32_t dst = (uint32_t)data[16] << 24 | (uint32_t)data[17] << 16 |
                   (uint32_t)data[18] <<  8 | (uint32_t)data[19];
    uint16_t total_len = (uint16_t)data[2] << 8 | data[3];

    const char* proto_name = "???";
    switch (proto) {
        case 1:  proto_name = "ICMP"; break;
        case 6:  proto_name = "TCP";  break;
        case 17: proto_name = "UDP";  break;
    }

    auto ip_str = [](uint32_t ip, char* out, size_t out_len) {
        std::snprintf(out, out_len, "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >>  8) & 0xFF,  ip        & 0xFF);
    };

    char src_str[16], dst_str[16];
    ip_str(src, src_str, sizeof(src_str));
    ip_str(dst, dst_str, sizeof(dst_str));

    printf("[pkt] %s -> %s | %s | len=%u | hdr=%u | raw=",
           src_str, dst_str, proto_name, total_len,
           (version_ihl & 0x0F) * 4);

    size_t dump = (len > 64) ? 64 : len;
    for (size_t i = 0; i < dump; i++)
        printf("%02x", data[i]);
    putchar('\n');
}
