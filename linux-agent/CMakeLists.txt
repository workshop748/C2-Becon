cmake_minimum_required(VERSION 3.16)
project(linux_agent C)

set(CMAKE_C_STANDARD 11)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(agent
    src/main_linux.c
    src/comms_linux.c
    src/crypto_linux.c
    src/recon_linux.c
    src/tasks_linux.c
    src/persist_linux.c
)

target_include_directories(agent PRIVATE include)
target_link_libraries(agent CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(agent PRIVATE -O2 -s -Wall)
