// tools/hash_gen.c — compile and run on Windows or via Wine
#include <windows.h>
#include <stdio.h>

#define INITIAL_SEED 5

static unsigned int _Rotr32(unsigned int v, unsigned int c) {
    unsigned int mask = 31;
    c &= mask;
    return (v >> c) | (v << ((-c) & mask));
}

int HashA(const char* s) {
    int v = 0;
    for (int i = 0; s[i]; i++)
        v = s[i] + _Rotr32(v, INITIAL_SEED);
    return v;
}

int HashW(const wchar_t* s) {
    int v = 0;
    for (int i = 0; s[i]; i++)
        v = s[i] + _Rotr32(v, INITIAL_SEED);
    return v;
}

int main() {
    printf("#define WINHTTP_DLL_HASH          0x%08X\n", HashW(L"WINHTTP.DLL"));
    printf("#define WinHttpOpen_HASH          0x%08X\n", HashA("WinHttpOpen"));
    printf("#define WinHttpConnect_HASH       0x%08X\n", HashA("WinHttpConnect"));
    printf("#define WinHttpOpenRequest_HASH   0x%08X\n", HashA("WinHttpOpenRequest"));
    printf("#define WinHttpSendRequest_HASH   0x%08X\n", HashA("WinHttpSendRequest"));
    printf("#define WinHttpReceiveResponse_HASH 0x%08X\n", HashA("WinHttpReceiveResponse"));
    printf("#define WinHttpReadData_HASH      0x%08X\n", HashA("WinHttpReadData"));
    printf("#define WinHttpCloseHandle_HASH   0x%08X\n", HashA("WinHttpCloseHandle"));
    printf("#define WinHttpQueryHeaders_HASH  0x%08X\n", HashA("WinHttpQueryHeaders"));
    return 0;
}
