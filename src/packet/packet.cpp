#include "aegis/packet.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

PacketEngine::PacketEngine() = default;

bool PacketEngine::parse_ip_packet(
    const std::vector<uint8_t>& raw, IPPacket& out
) const {
    if (raw.size() < sizeof(IPPacket)) return false;
    std::memcpy(&out, raw.data(), sizeof(IPPacket));
    return true;
}

EncryptedFrame PacketEngine::create_frame(
    const PacketHeader& header,
    const std::vector<uint8_t>& plaintext
) const {
    EncryptedFrame frame;
    frame.header = header;
    (void)plaintext;
    return frame;
}

OnionLayer PacketEngine::wrap_for_relay(
    const NodeId& next_hop,
    const std::vector<uint8_t>& inner
) const {
    OnionLayer layer;
    layer.next_hop = next_hop;
    layer.inner = inner;
    return layer;
}

std::vector<uint8_t> PacketEngine::serialize_frame(
    const EncryptedFrame& frame
) const {
    std::vector<uint8_t> buf(sizeof(PacketHeader));
    std::memcpy(buf.data(), &frame.header, sizeof(PacketHeader));
    return buf;
}

std::vector<uint8_t> PacketEngine::serialize_onion(
    const OnionLayer& layer
) const {
    std::vector<uint8_t> buf(NODE_ID_SIZE + layer.inner.size());
    std::memcpy(buf.data(), layer.next_hop.data(), NODE_ID_SIZE);
    std::memcpy(buf.data() + NODE_ID_SIZE, layer.inner.data(), layer.inner.size());
    return buf;
}

bool PacketEngine::deserialize_header(
    const std::vector<uint8_t>& data, PacketHeader& out
) const {
    if (data.size() < sizeof(PacketHeader)) return false;
    std::memcpy(&out, data.data(), sizeof(PacketHeader));
    return true;
}
