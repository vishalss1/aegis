#include "aegis/protocol/endpoint_candidate.hpp"
#include "aegis/protocol/endpoint_punch.hpp"
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

class ManualClock final : public ProtocolClock {
public:
    [[nodiscard]] time_point now() const noexcept override { return now_; }
    void advance(std::chrono::seconds duration) { now_ += duration; }

private:
    time_point now_{};
};

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
    // The wire format is IPv4-only: IPv6 candidates fail closed.
    CHECK(!serialize_endpoint_candidates({
        message.subject,
        {{EndpointCandidateType::Host,
          Endpoint(*IPAddress::parse("2001:db8::7"), htons(5000)), 1}}}));
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

    const EndpointPunchMessage challenge{
        EndpointPunchKind::Challenge, 0x0102030405060708ULL};
    const auto punch_bytes = serialize_endpoint_punch(challenge);
    CHECK(punch_bytes && punch_bytes->size() == ENDPOINT_PUNCH_WIRE_SIZE);
    const auto decoded_punch = punch_bytes
        ? deserialize_endpoint_punch(*punch_bytes) : std::nullopt;
    CHECK(decoded_punch && decoded_punch->kind == challenge.kind);
    CHECK(decoded_punch &&
          decoded_punch->transaction_id == challenge.transaction_id);
    CHECK(!serialize_endpoint_punch({EndpointPunchKind::Challenge, 0}));
    if (punch_bytes) {
        auto bad_version = *punch_bytes;
        bad_version[0] = 2;
        CHECK(!deserialize_endpoint_punch(bad_version));
        auto bad_reserved = *punch_bytes;
        bad_reserved[2] = 1;
        CHECK(!deserialize_endpoint_punch(bad_reserved));
        auto bad_kind = *punch_bytes;
        bad_kind[1] = 3;
        CHECK(!deserialize_endpoint_punch(bad_kind));
        auto truncated = *punch_bytes;
        truncated.pop_back();
        CHECK(!deserialize_endpoint_punch(truncated));
    }

    {
        ManualClock clock;
        EndpointPunchTracker tracker(2, std::chrono::seconds(5));
        const EndpointPunchTarget target{
            make_id(8), Endpoint::from_parts(198, 51, 100, 8, 62008)};
        CHECK(tracker.begin(17, target, clock.now()));
        CHECK(!tracker.begin(18, target, clock.now()));
        CHECK(!tracker.acknowledge(
            17, make_id(9), target.endpoint, clock.now()));
        CHECK(!tracker.acknowledge(
            17, target.peer_id,
            Endpoint::from_parts(198, 51, 100, 9, 62008), clock.now()));
        clock.advance(std::chrono::seconds(4));
        const auto accepted = tracker.acknowledge(
            17, target.peer_id, target.endpoint, clock.now());
        CHECK(accepted && *accepted == target);
        CHECK(tracker.size() == 0);

        CHECK(tracker.begin(19, target, clock.now()));
        clock.advance(std::chrono::seconds(5));
        CHECK(!tracker.acknowledge(
            19, target.peer_id, target.endpoint, clock.now()));
        const auto expired = tracker.expire(clock.now());
        CHECK(expired.size() == 1 && expired[0] == 19);
        CHECK(tracker.size() == 0);
    }

    std::printf("\n%d / %d passed\n", passed, tests);
    return passed == tests ? 0 : 1;
}
