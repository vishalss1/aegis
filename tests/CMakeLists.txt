add_executable(test_packet test_packet.cpp ../src/packet/packet.cpp)
target_include_directories(test_packet PRIVATE ../include)

add_test(NAME test_packet COMMAND test_packet)

add_custom_target(check
    COMMAND test_packet
    COMMENT "Running packet parse tests"
)
