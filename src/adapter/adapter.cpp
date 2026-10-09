#include "aegis/adapter/adapter.hpp"
#include "aegis/packet/mtu.hpp"
#include "aegis/packet/packet.hpp"

Adapter::Adapter() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

Adapter::~Adapter() { close(); }

static void CALLBACK wintun_log(_In_ WINTUN_LOGGER_LEVEL Level,
                                _In_ DWORD64 Timestamp,
                                _In_z_ LPCWSTR Message) {
    (void)Timestamp;
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

bool Adapter::create(uint32_t ip, uint8_t prefix, const wchar_t* adapter_name,
                     uint32_t mtu) {
    return create(IPInterfaceAddress{
                      IPAddress::from_ipv4(ntohl(ip)), prefix},
                  adapter_name, mtu);
}

bool Adapter::create(const IPInterfaceAddress& address,
                     const wchar_t* adapter_name,
                     uint32_t mtu) {
    if (!address.valid()) {
        fprintf(stderr, "[adapter] invalid overlay prefix\n");
        return false;
    }
    const bool ipv6 = address.address.family == IPAddressFamily::IPv6;
    const uint32_t minimum_mtu = ipv6 ? 1280 : MINIMUM_IPV4_MTU;
    if (mtu < minimum_mtu || mtu > MAXIMUM_IPV4_MTU) {
        fprintf(stderr, "[adapter] invalid IPv%u MTU %u (minimum %u)\n",
                ipv6 ? 6 : 4, mtu, minimum_mtu);
        return false;
    }
    fprintf(stderr, "[adapter] create: loading dll\n");
    if (!load_wintun_dll())
        return false;

    WintunSetLogger_(wintun_log);
    fprintf(stderr, "[adapter] logger set\n");

    fprintf(stderr, "[adapter] create: calling WintunCreateAdapter\n");
    adapter_ = WintunCreateAdapter_(adapter_name, L"Aegis", nullptr);
    if (!adapter_) {
        fprintf(stderr, "[adapter] WintunCreateAdapter failed (error %lu)\n",
                GetLastError());
        return false;
    }
    fprintf(stderr, "[adapter] adapter created\n");

    NET_LUID luid{};
    WintunGetAdapterLUID_(adapter_, &luid);

    // Wait for the interface to be ready for IP config
    for (int i = 0; i < 50; i++) {
        ULONG bufLen = 0;
        GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen);
        std::vector<uint8_t> buf(bufLen);
        PIP_ADAPTER_ADDRESSES addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        ULONG ret = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &bufLen);
        if (ret == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = addrs; a; a = a->Next) {
                if (a->Luid.Value != luid.Value) continue;
                if (ipv6 && a->Ipv6IfIndex != 0)
                    if_index_ = a->Ipv6IfIndex;
                else if (!ipv6 && a->IfIndex != 0)
                    if_index_ = a->IfIndex;
                if (if_index_ != 0) goto interface_ready;
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
    if (!configure_ip(address)) {
        close();
        return false;
    }
    if (!configure_mtu(mtu, ipv6 ? AF_INET6 : AF_INET)) {
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

    fprintf(stderr, "[adapter] up if_index=%lu family=IPv%u prefix=/%u mtu=%u\n",
            if_index_, ipv6 ? 6 : 4, address.prefix_length, mtu_);
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
    mtu_ = 0;
}

bool Adapter::configure_mtu(uint32_t mtu, ADDRESS_FAMILY family) {
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = family;
    row.InterfaceIndex = if_index_;

    ULONG ret = GetIpInterfaceEntry(&row);
    if (ret != NO_ERROR) {
        fprintf(stderr, "[adapter] GetIpInterfaceEntry failed (error %lu)\n",
                ret);
        return false;
    }
    row.SitePrefixLength = 0;
    row.NlMtu = mtu;
    ret = SetIpInterfaceEntry(&row);
    if (ret != NO_ERROR) {
        fprintf(stderr, "[adapter] SetIpInterfaceEntry(NlMtu=%u) failed "
                        "(error %lu)\n", mtu, ret);
        return false;
    }
    mtu_ = mtu;
    fprintf(stderr, "[adapter] IPv%u MTU %u configured\n",
            family == AF_INET6 ? 6 : 4, mtu_);
    return true;
}

bool Adapter::build_unicast_address_row(
    const IPInterfaceAddress& address, NET_IFINDEX interface_index,
    MIB_UNICASTIPADDRESS_ROW& row) noexcept {
    if (!address.valid() || interface_index == 0) return false;
    row = {};
    InitializeUnicastIpAddressEntry(&row);
    if (address.address.family == IPAddressFamily::IPv4) {
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = htonl(
            address.address.ipv4_value());
    } else if (address.address.family == IPAddressFamily::IPv6) {
        row.Address.Ipv6.sin6_family = AF_INET6;
        std::memcpy(&row.Address.Ipv6.sin6_addr,
                    address.address.bytes.data(), 16);
    } else {
        return false;
    }
    row.OnLinkPrefixLength = address.prefix_length;
    row.DadState = IpDadStatePreferred;
    row.InterfaceIndex = interface_index;
    return true;
}

bool Adapter::configure_ip(const IPInterfaceAddress& address) {
    MIB_UNICASTIPADDRESS_ROW row{};
    if (!build_unicast_address_row(address, if_index_, row))
        return false;

    ULONG ret = CreateUnicastIpAddressEntry(&row);
    if (ret == NO_ERROR) {
        fprintf(stderr, "[adapter] IPv%u prefix /%u configured\n",
                address.address.family == IPAddressFamily::IPv6 ? 6 : 4,
                address.prefix_length);
        return true;
    }
    if (ret == ERROR_OBJECT_ALREADY_EXISTS) {
        fprintf(stderr, "[adapter] IPv%u prefix /%u already configured\n",
                address.address.family == IPAddressFamily::IPv6 ? 6 : 4,
                address.prefix_length);
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
    auto ip_str = [](uint32_t ip, char* out, size_t out_len) {
        std::snprintf(out, out_len, "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >>  8) & 0xFF,  ip        & 0xFF);
    };

    auto parsed = IPPacket::parse(data, len);
    if (!parsed) {
        printf("[pkt] non-IPv4 (ver=%u  len=%zu) | raw=",
               (len >= 1) ? (unsigned)(data[0] >> 4) : 0, len);
        size_t dump = (len > 64) ? 64 : len;
        for (size_t i = 0; i < dump; i++)
            printf("%02x", data[i]);
        putchar('\n');
        return;
    }

    const IPPacket& pkt = *parsed;
    const char* proto_name = "???";
    switch (pkt.protocol) {
        case 1:  proto_name = "ICMP"; break;
        case 6:  proto_name = "TCP";  break;
        case 17: proto_name = "UDP";  break;
    }

    char src_str[16], dst_str[16];
    ip_str(pkt.source_ip, src_str, sizeof(src_str));
    ip_str(pkt.dest_ip, dst_str, sizeof(dst_str));

    printf("[pkt] %s -> %s | %s | len=%u | hdr=%u | raw=",
           src_str, dst_str, proto_name, pkt.total_length,
           (pkt.version_ihl & 0x0F) * 4);

    size_t dump = (len > 64) ? 64 : len;
    for (size_t i = 0; i < dump; i++)
        printf("%02x", data[i]);
    putchar('\n');
}
