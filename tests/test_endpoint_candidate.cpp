#include "aegis/protocol/endpoint_candidate.hpp"
#include <cstdio>

static int tests = 0;
static int passed = 0;

#define CHECK(cond) do { \
    tests++; \
    const bool ok = !!(cond); \
    passed += ok; \
    std::printf("  %s: %s\n", ok ? "PASS" : "FAIL", #cond); \
} while (0)

static NodeId make_id(uint8_t tag) {
    NodeId id{};
    id[0] = tag;
    return id;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("--- authenticated endpoint candidate tests ---\n");

    const EndpointCandidateMessage message{
        make_id(7),
        {
            {EndpointCandidateType::Host,
             Endpoint::from_parts(10, 0, 0, 7, 51820), 300},
            {EndpointCandidateType::ServerReflexive,
             Endpoint::from_parts(198, 51, 100, 7, 62000), 200},
            {EndpointCandidateType::PeerObserved,
             Endpoint::from_parts(203, 0, 113, 7, 62001), 400}
        }
    };
    const auto encoded = serialize_endpoint_candidates(message);
    CHECK(encoded.has_value());
    CHECK(encoded && encoded->size() ==
        ENDPOINT_CANDIDATE_HEADER_SIZE +
            3 * ENDPOINT_CANDIDATE_ENTRY_SIZE);
    const auto decoded = encoded
        ? deserialize_endpoint_candidates(*encoded) : std::nullopt;
    CHECK(decoded && decoded->subject == message.subject);
    CHECK(decoded && decoded->candidates == message.candidates);

    CHECK(gather_host_candidates(0).empty());
    CHECK(!serialize_endpoint_candidates({{}, message.candidates}));
    CHECK(!serialize_endpoint_candidates({message.subject, {}}));
    CHECK(!serialize_endpoint_candidates({
        message.subject,
        {{EndpointCandidateType::Host, Endpoint{}, 1}}}));
    CHECK(!serialize_endpoint_candidates({
        message.subject,
        {{EndpointCandidateType::Host,
          Endpoint::from_parts(224, 0, 0, 1, 5000), 1}}}));
    CHECK(!serialize_endpoint_candidates({
        message.subject,
        {message.candidates[0], message.candidates[0]}}));

    if (encoded) {
        auto bad_version = *encoded;
        bad_version[0] = 2;
        CHECK(!deserialize_endpoint_candidates(bad_version));
        auto bad_reserved = *encoded;
        bad_reserved[2] = 1;
        CHECK(!deserialize_endpoint_candidates(bad_reserved));
        auto bad_type = *encoded;
        bad_type[ENDPOINT_CANDIDATE_HEADER_SIZE] = 4;
        CHECK(!deserialize_endpoint_candidates(bad_type));
        auto truncated = *encoded;
        truncated.pop_back();
        CHECK(!deserialize_endpoint_candidates(truncated));
        auto extended = *encoded;
        extended.push_back(0);
        CHECK(!deserialize_endpoint_candidates(extended));
    }

    EndpointCandidateMessage too_many;
    too_many.subject = message.subject;
    for (size_t i = 0; i < ENDPOINT_CANDIDATE_MAX_COUNT + 1; ++i) {
        too_many.candidates.push_back({
            EndpointCandidateType::Host,
            Endpoint::from_parts(
                10, 0, 1, static_cast<uint8_t>(i + 1),
                static_cast<uint16_t>(5000 + i)),
            static_cast<uint32_t>(100 + i)});
    }
    CHECK(!serialize_endpoint_candidates(too_many));

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
