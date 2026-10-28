cmake_minimum_required(VERSION 3.20)
project(HighSpeedPacketSim LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization flags for high-throughput telecom packet processing
if (MSVC)
    add_compile_options(/W4 /O2 /Oi /Ot /GL)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3 -march=native)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Main executable target
add_executable(high_speed_packet_sim src/main.cpp)

# Test targets
add_executable(test_packet_buffer tests/test_packet_buffer.cpp)
add_executable(test_framework tests/test_framework.cpp)
add_executable(test_timing_wheel tests/test_timing_wheel.cpp)
add_executable(test_gtpu_processor tests/test_gtpu_processor.cpp)
add_executable(test_rlc_am tests/test_rlc_am.cpp)
add_executable(test_simulation tests/test_simulation.cpp)

enable_testing()
add_test(NAME TestPacketBuffer COMMAND test_packet_buffer)
add_test(NAME TestFramework COMMAND test_framework)
add_test(NAME TestTimingWheel COMMAND test_timing_wheel)
add_test(NAME TestGtpuProcessor COMMAND test_gtpu_processor)
add_test(NAME TestRlcAm COMMAND test_rlc_am)
add_test(NAME TestSimulation COMMAND test_simulation)
