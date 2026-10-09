#include "aegis/protocol/endpoint_candidate.hpp"
#include "aegis/protocol/wire.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <set>

namespace {

bool known_type(EndpointCandidateType type) noexcept {
    return type == EndpointCandidateType::Host ||
        type == EndpointCandidateType::ServerReflexive ||
        type == EndpointCandidateType::PeerObserved;
}

}  // namespace

bool valid_endpoint_candidate(
    const EndpointCandidate& candidate) noexcept {
    // The candidate wire format is IPv4-only until it is versioned.
    if (!known_type(candidate.type) || !candidate.endpoint.is_ipv4() ||
        candidate.endpoint.unspecified() ||
        candidate.endpoint.port == 0 || candidate.priority == 0)
        return false;
    const uint32_t ip = ntohl(candidate.endpoint.ipv4_network());
    return ip != 0xFFFFFFFFu && (ip & 0xF0000000u) != 0xE0000000u;
}

std::optional<std::vector<uint8_t>> serialize_endpoint_candidates(
    const EndpointCandidateMessage& message) {
    if (message.subject == NodeId{} || message.candidates.empty() ||
        message.candidates.size() > ENDPOINT_CANDIDATE_MAX_COUNT)
        return std::nullopt;
    std::set<std::pair<IPAddress, uint16_t>> endpoints;
    for (const auto& candidate : message.candidates) {
        if (!valid_endpoint_candidate(candidate) ||
            !endpoints.emplace(
                candidate.endpoint.address, candidate.endpoint.port).second)
            return std::nullopt;
    }

    std::vector<uint8_t> payload(
        ENDPOINT_CANDIDATE_HEADER_SIZE +
        message.candidates.size() * ENDPOINT_CANDIDATE_ENTRY_SIZE);
    WireWriter writer(payload);
    if (!writer.write_u8(ENDPOINT_CANDIDATE_VERSION) ||
        !writer.write_u8(static_cast<uint8_t>(message.candidates.size())) ||
        !writer.write_u16(0) || !writer.write_bytes(message.subject))
        return std::nullopt;
    for (const auto& candidate : message.candidates) {
        if (!writer.write_u8(static_cast<uint8_t>(candidate.type)) ||
            !writer.write_u8(0) ||
            !writer.write_u16(ntohs(candidate.endpoint.port)) ||
            !writer.write_u32(ntohl(candidate.endpoint.ipv4_network())) ||
            !writer.write_u32(candidate.priority))
            return std::nullopt;
    }
    if (!writer.finished())
        return std::nullopt;
    return payload;
}

std::optional<EndpointCandidateMessage> deserialize_endpoint_candidates(
    std::span<const uint8_t> payload) {
    WireReader reader(payload);
    const auto version = reader.read_u8();
    const auto count = reader.read_u8();
    const auto reserved = reader.read_u16();
    const auto subject = reader.read_bytes(NodeId{}.size());
    if (!version || !count || !reserved || !subject ||
        *version != ENDPOINT_CANDIDATE_VERSION || *count == 0 ||
        *count > ENDPOINT_CANDIDATE_MAX_COUNT || *reserved != 0 ||
        payload.size() != ENDPOINT_CANDIDATE_HEADER_SIZE +
            static_cast<size_t>(*count) * ENDPOINT_CANDIDATE_ENTRY_SIZE)
        return std::nullopt;

    EndpointCandidateMessage message;
    std::copy(subject->begin(), subject->end(), message.subject.begin());
    if (message.subject == NodeId{})
        return std::nullopt;
    std::set<std::pair<IPAddress, uint16_t>> endpoints;
    message.candidates.reserve(*count);
    for (size_t i = 0; i < *count; ++i) {
        const auto type = reader.read_u8();
        const auto entry_reserved = reader.read_u8();
        const auto port = reader.read_u16();
        const auto ip = reader.read_u32();
        const auto priority = reader.read_u32();
        if (!type || !entry_reserved || !port || !ip || !priority ||
            *entry_reserved != 0)
            return std::nullopt;
        EndpointCandidate candidate{
            static_cast<EndpointCandidateType>(*type),
            Endpoint{htonl(*ip), htons(*port)}, *priority};
        if (!valid_endpoint_candidate(candidate) ||
            !endpoints.emplace(
                candidate.endpoint.address, candidate.endpoint.port).second)
            return std::nullopt;
        message.candidates.push_back(candidate);
    }
    if (!reader.finished())
        return std::nullopt;
    return message;
}

std::vector<EndpointCandidate> gather_host_candidates(uint16_t local_port) {
    std::vector<EndpointCandidate> candidates;
    if (local_port == 0)
        return candidates;
    std::array<char, 256> hostname{};
    if (gethostname(hostname.data(), static_cast<int>(hostname.size())) != 0)
        return candidates;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(hostname.data(), nullptr, &hints, &addresses) != 0 ||
        !addresses)
        return candidates;

    std::set<uint32_t> seen;
    for (auto* current = addresses;
         current && candidates.size() < ENDPOINT_CANDIDATE_MAX_COUNT;
         current = current->ai_next) {
        if (!current->ai_addr || current->ai_addrlen < sizeof(sockaddr_in))
            continue;
        const auto* address =
            reinterpret_cast<const sockaddr_in*>(current->ai_addr);
        EndpointCandidate candidate{
            EndpointCandidateType::Host,
            Endpoint{address->sin_addr.s_addr, htons(local_port)},
            300u - static_cast<uint32_t>(candidates.size())};
        if (valid_endpoint_candidate(candidate) &&
            seen.insert(candidate.endpoint.ipv4_network()).second)
            candidates.push_back(candidate);
    }
    freeaddrinfo(addresses);
    return candidates;
}
