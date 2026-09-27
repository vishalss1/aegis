#include "aegis/session/handshake_v2.hpp"
#include "aegis/protocol/wire.hpp"
#include <algorithm>

namespace {

bool write_header(WireWriter& writer, uint8_t type, uint32_t session_id,
                  uint16_t payload_length) {
    return session_id != 0 &&
        writer.write_u8(HANDSHAKE_V2_VERSION) && writer.write_u8(type) &&
        writer.write_u8(HANDSHAKE_V2_FLAGS) &&
        writer.write_u32(session_id) && writer.write_u16(payload_length);
}

bool read_header(WireReader& reader, uint8_t expected_type,
                 uint16_t expected_payload_length, uint32_t& session_id) {
    const auto version = reader.read_u8();
    const auto type = reader.read_u8();
    const auto flags = reader.read_u8();
    const auto parsed_session_id = reader.read_u32();
    const auto payload_length = reader.read_u16();
    if (!version || !type || !flags || !parsed_session_id ||
        !payload_length || *version != HANDSHAKE_V2_VERSION ||
        *type != expected_type || *flags != HANDSHAKE_V2_FLAGS ||
        *parsed_session_id == 0 ||
        *payload_length != expected_payload_length) {
        return false;
    }
    session_id = *parsed_session_id;
    return true;
}

} // namespace

std::optional<std::array<uint8_t, HANDSHAKE_V2_INIT_FRAME_SIZE>>
serialize_handshake_v2_init(const HandshakeV2InitFrame& frame) {
    std::array<uint8_t, HANDSHAKE_V2_INIT_FRAME_SIZE> bytes{};
    WireWriter writer(bytes);
    if (!write_header(writer, HANDSHAKE_V2_INIT_TYPE, frame.session_id,
                      static_cast<uint16_t>(HANDSHAKE_V2_INIT_PAYLOAD_SIZE)) ||
        !writer.write_bytes(frame.network_id) ||
        !writer.write_bytes(frame.noise_message) || !writer.finished()) {
        return std::nullopt;
    }
    return bytes;
}

std::optional<HandshakeV2InitFrame> parse_handshake_v2_init(
    std::span<const uint8_t> bytes) {
    if (bytes.size() != HANDSHAKE_V2_INIT_FRAME_SIZE)
        return std::nullopt;

    WireReader reader(bytes);
    HandshakeV2InitFrame frame;
    if (!read_header(reader, HANDSHAKE_V2_INIT_TYPE,
                     static_cast<uint16_t>(HANDSHAKE_V2_INIT_PAYLOAD_SIZE),
                     frame.session_id)) {
        return std::nullopt;
    }

    const auto network_id = reader.read_bytes(NETWORK_ID_SIZE);
    const auto noise_message = reader.read_bytes(HANDSHAKE_V2_INIT_NOISE_SIZE);
    if (!network_id || !noise_message || !reader.finished())
        return std::nullopt;

    std::copy(network_id->begin(), network_id->end(), frame.network_id.begin());
    std::copy(noise_message->begin(), noise_message->end(),
              frame.noise_message.begin());
    return frame;
}

std::optional<std::array<uint8_t, HANDSHAKE_V2_RESPONSE_FRAME_SIZE>>
serialize_handshake_v2_response(const HandshakeV2ResponseFrame& frame) {
    std::array<uint8_t, HANDSHAKE_V2_RESPONSE_FRAME_SIZE> bytes{};
    WireWriter writer(bytes);
    if (!write_header(
            writer, HANDSHAKE_V2_RESPONSE_TYPE, frame.session_id,
            static_cast<uint16_t>(HANDSHAKE_V2_RESPONSE_PAYLOAD_SIZE)) ||
        !writer.write_bytes(frame.noise_message) || !writer.finished()) {
        return std::nullopt;
    }
    return bytes;
}

std::optional<HandshakeV2ResponseFrame> parse_handshake_v2_response(
    std::span<const uint8_t> bytes) {
    if (bytes.size() != HANDSHAKE_V2_RESPONSE_FRAME_SIZE)
        return std::nullopt;

    WireReader reader(bytes);
    HandshakeV2ResponseFrame frame;
    if (!read_header(
            reader, HANDSHAKE_V2_RESPONSE_TYPE,
            static_cast<uint16_t>(HANDSHAKE_V2_RESPONSE_PAYLOAD_SIZE),
            frame.session_id)) {
        return std::nullopt;
    }

    const auto noise_message =
        reader.read_bytes(HANDSHAKE_V2_RESPONSE_NOISE_SIZE);
    if (!noise_message || !reader.finished())
        return std::nullopt;

    std::copy(noise_message->begin(), noise_message->end(),
              frame.noise_message.begin());
    return frame;
}
