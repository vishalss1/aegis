#pragma once

#include <cstdint>

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t version;
    uint8_t packet_type;
    uint8_t flags;
    uint8_t reserved;
    uint32_t session_id;
    uint32_t sequence_number;
    uint32_t payload_length;
};
#pragma pack(pop)

static constexpr uint8_t PACKET_VERSION = 0x01;

static constexpr uint8_t TYPE_HANDSHAKE_INIT = 0x00;
static constexpr uint8_t TYPE_HANDSHAKE_RESP = 0x01;
static constexpr uint8_t TYPE_DATA = 0x02;
static constexpr uint8_t TYPE_KEEPALIVE = 0x03;
static constexpr uint8_t TYPE_DISCOVERY = 0x04;
static constexpr uint8_t TYPE_PEER_TABLE = 0x05;
static constexpr uint8_t TYPE_RELAY = 0x06;

static constexpr uint8_t FLAG_RELAY = 0x01;
static constexpr uint8_t FLAG_FRAGMENTED = 0x02;
