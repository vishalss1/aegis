#include "aegis/cli/input_parser.hpp"
#include "aegis/cli/command_registry.hpp"
#include "aegis/cli/identity_store.hpp"
#include "aegis/cli/commands.hpp"
#include "aegis/invite/invite.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>

void test_input_parser_command() {
    ParsedInput res = parse_cli_input("/help");
    assert(res.mode == InputMode::Command);
    assert(res.command == "help");
    assert(res.args.empty());
    assert(!res.is_bare_slash);
    printf("[test_cli] test_input_parser_command passed\n");
}

void test_input_parser_args() {
    ParsedInput res = parse_cli_input("/connect AEGIS1:abc \"foo bar\"");
    assert(res.mode == InputMode::Command);
    assert(res.command == "connect");
    assert(res.args.size() == 2);
    assert(res.args[0] == "AEGIS1:abc");
    assert(res.args[1] == "foo bar");
    printf("[test_cli] test_input_parser_args passed\n");
}

void test_input_parser_message() {
    ParsedInput res = parse_cli_input("hello world");
    assert(res.mode == InputMode::Message);
    assert(res.raw_text == "hello world");
    assert(!res.is_bare_slash);
    printf("[test_cli] test_input_parser_message passed\n");
}

void test_input_parser_bare_slash() {
    ParsedInput res = parse_cli_input("/");
    assert(res.mode == InputMode::Command);
    assert(res.is_bare_slash);
    printf("[test_cli] test_input_parser_bare_slash passed\n");
}

void test_unknown_command() {
    CommandRegistry registry;
    register_cli_commands(registry);

    CliContext ctx;
    ParsedInput input = parse_cli_input("/unknown_command_123");
    bool dispatched = registry.dispatch(input, ctx);
    assert(!dispatched);
    printf("[test_cli] test_unknown_command passed\n");
}

void test_help_lists_all_commands() {
    CommandRegistry registry;
    register_cli_commands(registry);

    assert(registry.has_command("help"));
    assert(registry.has_command("config"));
    assert(registry.has_command("delete"));
    assert(registry.has_command("leave"));
    assert(registry.has_command("discover"));
    assert(registry.has_command("invite"));
    assert(registry.has_command("connect"));
    assert(registry.has_command("sendfile"));
    assert(registry.has_command("peers"));
    assert(registry.has_command("status"));
    assert(registry.has_command("identity"));
    assert(registry.has_command("quit"));
    assert(registry.has_command("exit"));
    printf("[test_cli] test_help_lists_all_commands passed\n");
}

void test_identity_store_roundtrip() {
    std::string temp_file = "temp_test_identity.bin";
    std::remove(temp_file.c_str());

    NetworkId nid{};
    nid[0] = 0xAB;
    nid[31] = 0xCD;

    Identity id1 = load_or_create_identity(nid, temp_file);
    Identity id2 = load_or_create_identity(nid, temp_file);

    assert(id1.node_id == id2.node_id);
    assert(id1.keypair.public_key == id2.keypair.public_key);
    assert(id1.keypair.private_key == id2.keypair.private_key);
    assert(id1.signing_keypair.public_key == id2.signing_keypair.public_key);
    assert(id1.signing_keypair.private_key == id2.signing_keypair.private_key);
    assert(id1.key_agreement_binding == id2.key_agreement_binding);
    assert(verify_key_agreement_binding(id1));
    assert(verify_key_agreement_binding(id2));

    std::ifstream stored(temp_file, std::ios::binary | std::ios::ate);
    assert(stored.is_open());
    assert(static_cast<std::streamoff>(stored.tellg()) == 168);
    stored.seekg(0);
    char magic[8]{};
    stored.read(magic, sizeof(magic));
    assert(std::string(magic, 7) == "AEGISID");
    assert(static_cast<unsigned char>(magic[7]) == 1);
    stored.close();

    std::remove(temp_file.c_str());
    printf("[test_cli] test_identity_store_roundtrip passed\n");
}

void test_legacy_identity_migration() {
    const std::string temp_file = "temp_legacy_identity.bin";
    std::remove(temp_file.c_str());
    NetworkId network{};
    network[0] = 0x5A;
    const Identity legacy = Identity::create(network);
    {
        std::ofstream out(temp_file, std::ios::binary);
        assert(out.is_open());
        out.write(
            reinterpret_cast<const char*>(legacy.keypair.private_key.data()),
            static_cast<std::streamsize>(legacy.keypair.private_key.size()));
        assert(out.good());
    }

    const Identity migrated = load_or_create_identity(network, temp_file);
    assert(migrated.node_id == legacy.node_id);
    assert(migrated.keypair.private_key == legacy.keypair.private_key);
    assert(verify_key_agreement_binding(migrated));
    const Identity reloaded = load_or_create_identity(network, temp_file);
    assert(reloaded.node_id == migrated.node_id);
    assert(reloaded.signing_keypair.public_key ==
           migrated.signing_keypair.public_key);
    assert(reloaded.signing_keypair.private_key ==
           migrated.signing_keypair.private_key);

    std::remove(temp_file.c_str());
    printf("[test_cli] test_legacy_identity_migration passed\n");
}

void test_corrupt_identity_fails_closed() {
    const std::string temp_file = "temp_corrupt_identity.bin";
    std::remove(temp_file.c_str());
    {
        std::ofstream out(temp_file, std::ios::binary);
        const char corrupt[] = "bad";
        out.write(corrupt, sizeof(corrupt));
    }
    bool rejected = false;
    try {
        (void)load_or_create_identity(NetworkId{}, temp_file);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    std::ifstream in(temp_file, std::ios::binary | std::ios::ate);
    assert(in.is_open() && static_cast<std::streamoff>(in.tellg()) == 4);
    in.close();
    std::remove(temp_file.c_str());

    (void)load_or_create_identity(NetworkId{}, temp_file);
    {
        std::fstream file(
            temp_file, std::ios::binary | std::ios::in | std::ios::out);
        assert(file.is_open());
        file.seekg(167);
        char byte = 0;
        file.read(&byte, 1);
        assert(file.gcount() == 1);
        byte ^= 0x01;
        file.seekp(167);
        file.write(&byte, 1);
        assert(file.good());
    }
    rejected = false;
    try {
        (void)load_or_create_identity(NetworkId{}, temp_file);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    in.open(temp_file, std::ios::binary | std::ios::ate);
    assert(in.is_open() && static_cast<std::streamoff>(in.tellg()) == 168);
    in.close();
    std::remove(temp_file.c_str());
    printf("[test_cli] test_corrupt_identity_fails_closed passed\n");
}

void test_invite_trimming() {
    InvitePayload payload{};
    payload.network_id[0] = 1;
    payload.bootstrap_pubkey[0] = 2;
    payload.network_name = "Test Net";
    payload.bootstrap_endpoint = Endpoint{0x7F000001, htons(51820)};
    payload.bootstrap_prefix = 0x0A0A0001;
    payload.bootstrap_prefix_len = 24;

    std::string invite = encode_invite(payload);
    std::string dirty_invite = "  \"" + invite + "\"\r\n ";

    auto decoded = decode_invite(dirty_invite);
    assert(decoded.has_value());
    assert(decoded->network_id == payload.network_id);
    assert(decoded->bootstrap_pubkey == payload.bootstrap_pubkey);
    assert(decoded->network_name == "Test Net");
    assert(decoded->bootstrap_endpoint.port == payload.bootstrap_endpoint.port);
    printf("[test_cli] test_invite_trimming passed\n");
}

int main() {
    printf("[test_cli] Starting CLI unit tests...\n");
    test_input_parser_command();
    test_input_parser_args();
    test_input_parser_message();
    test_input_parser_bare_slash();
    test_unknown_command();
    test_help_lists_all_commands();
    test_identity_store_roundtrip();
    test_legacy_identity_migration();
    test_corrupt_identity_fails_closed();
    test_invite_trimming();
    printf("[test_cli] ALL CLI TESTS PASSED\n");
    return 0;
}
