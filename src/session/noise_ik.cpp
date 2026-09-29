#include "aegis/session/noise_ik.hpp"
#include "aegis/crypto/secret.hpp"
#include <noise/protocol.h>
#include <noise/protocol/aegis.h>
#include <utility>
#include <vector>

namespace {

constexpr char NOISE_IK_PROTOCOL_NAME[] =
    "Noise_IK_25519_ChaChaPoly_BLAKE2s";

NoiseIkError map_noise_error(int error) {
    switch (error) {
    case NOISE_ERROR_NONE:
        return NoiseIkError::none;
    case NOISE_ERROR_INVALID_PARAM:
    case NOISE_ERROR_INVALID_LENGTH:
        return NoiseIkError::invalid_argument;
    case NOISE_ERROR_INVALID_STATE:
        return NoiseIkError::invalid_state;
    case NOISE_ERROR_MAC_FAILURE:
    case NOISE_ERROR_INVALID_PUBLIC_KEY:
        return NoiseIkError::authentication_failed;
    default:
        return NoiseIkError::dependency_failure;
    }
}

} // namespace

struct NoiseIkHandshake::Impl {
    NoiseHandshakeState* state = nullptr;

    void reset() {
        if (state) {
            noise_handshakestate_free(state);
            state = nullptr;
        }
    }

    ~Impl() { reset(); }
};

NoiseIkHandshake::NoiseIkHandshake(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

NoiseIkHandshake::NoiseIkHandshake(NoiseIkHandshake&&) noexcept = default;
NoiseIkHandshake& NoiseIkHandshake::operator=(NoiseIkHandshake&&) noexcept =
    default;
NoiseIkHandshake::~NoiseIkHandshake() = default;

std::unique_ptr<NoiseIkHandshake> NoiseIkHandshake::create_initiator(
    const X25519PrivateKey& local_static_private,
    const X25519Key& expected_responder_static,
    std::span<const uint8_t> prologue,
    RandomSource& random) {
    return create(NOISE_ROLE_INITIATOR, local_static_private,
                  &expected_responder_static, prologue, random);
}

std::unique_ptr<NoiseIkHandshake> NoiseIkHandshake::create_responder(
    const X25519PrivateKey& local_static_private,
    std::span<const uint8_t> prologue,
    RandomSource& random) {
    return create(NOISE_ROLE_RESPONDER, local_static_private, nullptr,
                  prologue, random);
}

std::unique_ptr<NoiseIkHandshake> NoiseIkHandshake::create(
    int role,
    const X25519PrivateKey& local_static_private,
    const X25519Key* expected_responder_static,
    std::span<const uint8_t> prologue,
    RandomSource& random) {
    if ((role == NOISE_ROLE_INITIATOR) !=
        (expected_responder_static != nullptr)) {
        return nullptr;
    }

    auto impl = std::make_unique<Impl>();
    if (noise_init() != NOISE_ERROR_NONE ||
        noise_handshakestate_new_by_name(
            &impl->state, NOISE_IK_PROTOCOL_NAME, role) != NOISE_ERROR_NONE ||
        !impl->state) {
        return nullptr;
    }

    NoiseDHState* local =
        noise_handshakestate_get_local_keypair_dh(impl->state);
    if (!local || noise_dhstate_set_keypair_private(
            local, local_static_private.data(),
            local_static_private.size()) != NOISE_ERROR_NONE) {
        return nullptr;
    }

    if (expected_responder_static) {
        NoiseDHState* remote =
            noise_handshakestate_get_remote_public_key_dh(impl->state);
        if (!remote || noise_dhstate_set_public_key(
                remote, expected_responder_static->data(),
                expected_responder_static->size()) != NOISE_ERROR_NONE) {
            return nullptr;
        }
    }

    const uint8_t empty_prologue = 0;
    const void* prologue_data = prologue.empty()
        ? static_cast<const void*>(&empty_prologue)
        : static_cast<const void*>(prologue.data());
    if (noise_handshakestate_set_prologue(
            impl->state, prologue_data, prologue.size()) != NOISE_ERROR_NONE) {
        return nullptr;
    }

    SecretBytes<X25519_KEY_SIZE> ephemeral_private;
    if (!random.fill(std::span<uint8_t>(ephemeral_private.data(),
                                        ephemeral_private.size()))) {
        return nullptr;
    }
    NoiseDHState* ephemeral =
        noise_handshakestate_get_fixed_ephemeral_dh(impl->state);
    if (!ephemeral || noise_dhstate_set_keypair_private(
            ephemeral, ephemeral_private.data(),
            ephemeral_private.size()) != NOISE_ERROR_NONE ||
        noise_handshakestate_start(impl->state) != NOISE_ERROR_NONE) {
        return nullptr;
    }

    return std::unique_ptr<NoiseIkHandshake>(
        new NoiseIkHandshake(std::move(impl)));
}

NoiseIkOperationResult NoiseIkHandshake::write_message(
    std::span<const uint8_t> payload,
    std::span<uint8_t> output) {
    if (!impl_ || !impl_->state)
        return {NoiseIkError::invalid_argument, 0};
    if (output.empty()) {
        impl_->reset();
        return {NoiseIkError::buffer_too_small, 0};
    }

    NoiseBuffer message_buffer;
    noise_buffer_set_output(message_buffer, output.data(), output.size());

    NoiseBuffer payload_buffer;
    NoiseBuffer* payload_pointer = nullptr;
    if (!payload.empty()) {
        noise_buffer_set_input(
            payload_buffer, const_cast<uint8_t*>(payload.data()),
            payload.size());
        payload_pointer = &payload_buffer;
    }

    const int error = noise_handshakestate_write_message(
        impl_->state, &message_buffer, payload_pointer);
    if (error == NOISE_ERROR_NONE)
        return {NoiseIkError::none, message_buffer.size};

    const NoiseIkError mapped = error == NOISE_ERROR_INVALID_LENGTH
        ? NoiseIkError::buffer_too_small
        : map_noise_error(error);
    impl_->reset();
    return {mapped, 0};
}

NoiseIkOperationResult NoiseIkHandshake::read_message(
    std::span<const uint8_t> message,
    std::span<uint8_t> payload_output) {
    if (!impl_ || !impl_->state)
        return {NoiseIkError::invalid_argument, 0};
    if (message.empty()) {
        impl_->reset();
        return {NoiseIkError::invalid_argument, 0};
    }

    std::vector<uint8_t> mutable_message(message.begin(), message.end());
    NoiseBuffer message_buffer;
    noise_buffer_set_input(message_buffer, mutable_message.data(),
                           mutable_message.size());

    uint8_t empty_payload = 0;
    NoiseBuffer payload_buffer;
    noise_buffer_set_output(
        payload_buffer,
        payload_output.empty() ? &empty_payload : payload_output.data(),
        payload_output.size());

    const int error = noise_handshakestate_read_message(
        impl_->state, &message_buffer, &payload_buffer);
    if (error == NOISE_ERROR_NONE)
        return {NoiseIkError::none, payload_buffer.size};

    const NoiseIkError mapped = error == NOISE_ERROR_INVALID_LENGTH
        ? NoiseIkError::buffer_too_small
        : map_noise_error(error);
    impl_->reset();
    return {mapped, 0};
}

std::optional<X25519Key> NoiseIkHandshake::remote_static_public_key() const {
    if (!impl_ || !impl_->state)
        return std::nullopt;
    const int role = noise_handshakestate_get_role(impl_->state);
    const int action = noise_handshakestate_get_action(impl_->state);
    const bool authenticated =
        action == NOISE_ACTION_SPLIT || action == NOISE_ACTION_COMPLETE ||
        (role == NOISE_ROLE_RESPONDER &&
         action == NOISE_ACTION_WRITE_MESSAGE);
    if (!authenticated)
        return std::nullopt;
    NoiseDHState* remote =
        noise_handshakestate_get_remote_public_key_dh(impl_->state);
    if (!remote || !noise_dhstate_has_public_key(remote))
        return std::nullopt;

    X25519Key key{};
    if (noise_dhstate_get_public_key(remote, key.data(), key.size()) !=
        NOISE_ERROR_NONE) {
        return std::nullopt;
    }
    return key;
}

std::optional<std::array<uint8_t, NOISE_IK_HASH_SIZE>>
NoiseIkHandshake::handshake_hash() const {
    if (!impl_ || !impl_->state)
        return std::nullopt;

    std::array<uint8_t, NOISE_IK_HASH_SIZE> hash{};
    const int error = noise_handshakestate_get_handshake_hash(
        impl_->state, hash.data(), hash.size());
    if (error != NOISE_ERROR_NONE)
        return std::nullopt;
    return hash;
}

std::optional<NoiseIkSplitResult> NoiseIkHandshake::split() {
    if (!impl_ || !impl_->state)
        return std::nullopt;

    const auto remote = remote_static_public_key();
    const auto hash = handshake_hash();
    if (!remote || !hash)
        return std::nullopt;

    NoiseCipherState* send = nullptr;
    NoiseCipherState* receive = nullptr;
    if (noise_handshakestate_split(
            impl_->state, &send, &receive) != NOISE_ERROR_NONE ||
        !send || !receive) {
        if (send)
            noise_cipherstate_free(send);
        if (receive)
            noise_cipherstate_free(receive);
        impl_->reset();
        return std::nullopt;
    }

    NoiseIkSplitResult result;
    result.remote_static_public_key = *remote;
    result.handshake_hash = *hash;
    const bool exported =
        aegis_noise_cipherstate_export_key(
            send, result.send_key.data(), result.send_key.size()) ==
            NOISE_ERROR_NONE &&
        aegis_noise_cipherstate_export_key(
            receive, result.receive_key.data(), result.receive_key.size()) ==
            NOISE_ERROR_NONE;

    noise_cipherstate_free(send);
    noise_cipherstate_free(receive);
    impl_->reset();

    if (!exported)
        return std::nullopt;
    return result;
}
