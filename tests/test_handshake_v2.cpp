#include "aegis/session/handshake_v2.hpp"
#include <cstdio>
#include <vector>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    bool ok = !!(cond); \
    passed += ok; \
    printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("--- handshake v2 framing tests ---\n");

    HandshakeV2InitFrame init;
    init.session_id = 0x01020304;
    for (size_t i = 0; i < init.network_id.size(); ++i)
        init.network_id[i] = static_cast<uint8_t>(0x20 + i);
    for (size_t i = 0; i < init.noise_message.size(); ++i)
        init.noise_message[i] = static_cast<uint8_t>(i);

    const auto prologue =
        make_handshake_v2_prologue(init.network_id, init.session_id);
    CHECK(prologue.has_value());
    if (!prologue)
        return 1;
    CHECK(prologue->size() == HANDSHAKE_V2_PROLOGUE_SIZE);

    size_t offset = 0;
    CHECK((*prologue)[offset++] == HANDSHAKE_V2_PROLOGUE_DOMAIN.size());
    CHECK(std::equal(HANDSHAKE_V2_PROLOGUE_DOMAIN.begin(),
                     HANDSHAKE_V2_PROLOGUE_DOMAIN.end(),
                     prologue->begin() + offset));
    offset += HANDSHAKE_V2_PROLOGUE_DOMAIN.size();
    CHECK((*prologue)[offset++] == HANDSHAKE_V2_NOISE_PROTOCOL.size());
    CHECK(std::equal(HANDSHAKE_V2_NOISE_PROTOCOL.begin(),
                     HANDSHAKE_V2_NOISE_PROTOCOL.end(),
                     prologue->begin() + offset));
    offset += HANDSHAKE_V2_NOISE_PROTOCOL.size();
    CHECK((*prologue)[offset++] == HANDSHAKE_V2_VERSION);
    CHECK(std::equal(init.network_id.begin(), init.network_id.end(),
                     prologue->begin() + offset));
    offset += init.network_id.size();
    CHECK((*prologue)[offset] == 0x01 && (*prologue)[offset + 1] == 0x02 &&
          (*prologue)[offset + 2] == 0x03 &&
          (*prologue)[offset + 3] == 0x04);
    offset += 4;
    CHECK((*prologue)[offset++] == HANDSHAKE_V2_INITIATOR_ROLE);
    CHECK((*prologue)[offset++] == HANDSHAKE_V2_RESPONDER_ROLE);
    CHECK((*prologue)[offset] == HANDSHAKE_V2_VERSION &&
          (*prologue)[offset + 1] == HANDSHAKE_V2_INIT_TYPE &&
          (*prologue)[offset + 2] == HANDSHAKE_V2_FLAGS &&
          (*prologue)[offset + 7] == 0x00 &&
          (*prologue)[offset + 8] == 0x80);
    offset += HANDSHAKE_V2_HEADER_SIZE;
    CHECK((*prologue)[offset] == HANDSHAKE_V2_VERSION &&
          (*prologue)[offset + 1] == HANDSHAKE_V2_RESPONSE_TYPE &&
          (*prologue)[offset + 2] == HANDSHAKE_V2_FLAGS &&
          (*prologue)[offset + 7] == 0x00 &&
          (*prologue)[offset + 8] == 0x30);
    offset += HANDSHAKE_V2_HEADER_SIZE;
    CHECK(offset == prologue->size());

    const auto encoded_init = serialize_handshake_v2_init(init);
    CHECK(encoded_init.has_value());
    if (!encoded_init)
        return 1;
    CHECK(encoded_init->size() == HANDSHAKE_V2_INIT_FRAME_SIZE);
    CHECK((*encoded_init)[0] == HANDSHAKE_V2_VERSION);
    CHECK((*encoded_init)[1] == HANDSHAKE_V2_INIT_TYPE);
    CHECK((*encoded_init)[2] == HANDSHAKE_V2_FLAGS);
    CHECK((*encoded_init)[3] == 0x01 && (*encoded_init)[4] == 0x02 &&
          (*encoded_init)[5] == 0x03 && (*encoded_init)[6] == 0x04);
    CHECK((*encoded_init)[7] == 0x00 && (*encoded_init)[8] == 0x80);

    const auto parsed_init = parse_handshake_v2_init(*encoded_init);
    CHECK(parsed_init.has_value());
    CHECK(parsed_init && parsed_init->session_id == init.session_id);
    CHECK(parsed_init && parsed_init->network_id == init.network_id);
    CHECK(parsed_init && parsed_init->noise_message == init.noise_message);

    HandshakeV2ResponseFrame response;
    response.session_id = init.session_id;
    for (size_t i = 0; i < response.noise_message.size(); ++i)
        response.noise_message[i] = static_cast<uint8_t>(0xa0 + i);

    const auto encoded_response = serialize_handshake_v2_response(response);
    CHECK(encoded_response.has_value());
    if (!encoded_response)
        return 1;
    CHECK(encoded_response->size() == HANDSHAKE_V2_RESPONSE_FRAME_SIZE);
    CHECK((*encoded_response)[1] == HANDSHAKE_V2_RESPONSE_TYPE);
    CHECK((*encoded_response)[7] == 0x00 && (*encoded_response)[8] == 0x30);

    const auto parsed_response =
        parse_handshake_v2_response(*encoded_response);
    CHECK(parsed_response.has_value());
    CHECK(parsed_response && parsed_response->session_id == response.session_id);
    CHECK(parsed_response &&
          parsed_response->noise_message == response.noise_message);

    // Exact frame sizes and canonical header fields are mandatory.
    std::vector<uint8_t> malformed(encoded_init->begin(), encoded_init->end());
    malformed.pop_back();
    CHECK(!parse_handshake_v2_init(malformed).has_value());
    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed.push_back(0);
    CHECK(!parse_handshake_v2_init(malformed).has_value());

    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed[0] = 1;
    CHECK(!parse_handshake_v2_init(malformed).has_value());
    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed[1] = HANDSHAKE_V2_RESPONSE_TYPE;
    CHECK(!parse_handshake_v2_init(malformed).has_value());
    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed[2] = 1;
    CHECK(!parse_handshake_v2_init(malformed).has_value());
    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed[3] = 0;
    malformed[4] = 0;
    malformed[5] = 0;
    malformed[6] = 0;
    CHECK(!parse_handshake_v2_init(malformed).has_value());
    malformed.assign(encoded_init->begin(), encoded_init->end());
    malformed[8] = 0x7f;
    CHECK(!parse_handshake_v2_init(malformed).has_value());

    CHECK(!parse_handshake_v2_response(*encoded_init).has_value());

    malformed.assign(encoded_response->begin(), encoded_response->end());
    malformed.pop_back();
    CHECK(!parse_handshake_v2_response(malformed).has_value());
    malformed.assign(encoded_response->begin(), encoded_response->end());
    malformed.push_back(0);
    CHECK(!parse_handshake_v2_response(malformed).has_value());
    malformed.assign(encoded_response->begin(), encoded_response->end());
    malformed[0] = 1;
    CHECK(!parse_handshake_v2_response(malformed).has_value());
    malformed.assign(encoded_response->begin(), encoded_response->end());
    malformed[2] = 1;
    CHECK(!parse_handshake_v2_response(malformed).has_value());
    malformed.assign(encoded_response->begin(), encoded_response->end());
    malformed[8] = 0x2f;
    CHECK(!parse_handshake_v2_response(malformed).has_value());

    init.session_id = 0;
    response.session_id = 0;
    CHECK(!make_handshake_v2_prologue(init.network_id, 0).has_value());
    CHECK(!serialize_handshake_v2_init(init).has_value());
    CHECK(!serialize_handshake_v2_response(response).has_value());

    printf("--- handshake v2 framing: %d/%d passed ---\n", passed, tests);
    return passed == tests ? 0 : 1;
}
