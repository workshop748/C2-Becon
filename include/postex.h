// include/postex.h
#pragma once
#include "common.h"

BOOL postex_screenshot(OUT PBYTE* ppBmpData, OUT DWORD* pdwBmpSize);


BOOL postex_run(LPCSTR taskName);
