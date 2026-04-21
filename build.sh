#!/bin/bash
set -e

echo "[*] Building Windows beacon (cross-compile)..."
mkdir -p build && cd build
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=../mingw-w64.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel $(nproc)
echo "[+] beacon.exe and beacon.dll built"
cd ..

echo "[*] Building Linux agent..."
mkdir -p build_linux && cd build_linux
cmake ../linux-agent -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel $(nproc)
echo "[+] agent built"
cd ..

echo "[*] Running hash_gen to get WinHTTP hashes..."
gcc -o /tmp/hash_gen tools/hash_gen.c && /tmp/hash_gen
