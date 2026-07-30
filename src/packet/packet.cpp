#include "aegis/packet/packet.hpp"

uint16_t ip_checksum(const void* vdata, size_t len) {
    const uint16_t* data = static_cast<const uint16_t*>(vdata);
    uint32_t sum = 0;
    for (size_t i = 0; i < len / 2; i++) {
        sum += data[i];
    }
    if (len % 2) {
        sum += static_cast<const uint8_t*>(vdata)[len - 1];
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(sum);
}

std::optional<IPPacket> IPPacket::parse(const uint8_t* data, size_t len) {
    if (len < 20)
        return std::nullopt;

    uint8_t version = data[0] >> 4;
    if (version != 4)
        return std::nullopt;

    uint8_t ihl = data[0] & 0x0F;
    if (ihl < 5)
        return std::nullopt;

    size_t header_len = static_cast<size_t>(ihl) * 4;
    if (header_len > len)
        return std::nullopt;

    uint16_t total_len = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    if (total_len < header_len || total_len > len)
        return std::nullopt;

    if (ip_checksum(data, header_len) != 0xFFFF)
        return std::nullopt;

    IPPacket pkt;
    pkt.version_ihl = data[0];
    pkt.dscp_ecn = data[1];
    pkt.total_length = total_len;
    pkt.identification = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    pkt.flags_fragment_offset = (static_cast<uint16_t>(data[6]) << 8) | data[7];
    pkt.ttl = data[8];
    pkt.protocol = data[9];
    pkt.header_checksum = (static_cast<uint16_t>(data[10]) << 8) | data[11];
    pkt.source_ip = (static_cast<uint32_t>(data[12]) << 24) |
                    (static_cast<uint32_t>(data[13]) << 16) |
                    (static_cast<uint32_t>(data[14]) << 8) |
                    static_cast<uint32_t>(data[15]);
    pkt.dest_ip = (static_cast<uint32_t>(data[16]) << 24) |
                  (static_cast<uint32_t>(data[17]) << 16) |
                  (static_cast<uint32_t>(data[18]) << 8) |
                  static_cast<uint32_t>(data[19]);

    pkt.payload = data + header_len;
    pkt.payload_length = total_len - header_len;

    return pkt;
}
