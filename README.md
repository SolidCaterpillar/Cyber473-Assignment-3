# Proof-of-Concept Malware & Red Team Thinking 
**Course:** CYBER473  
**Student:** Ricky Fong  

> **Disclaimer:** This malware is developed solely for educational purposes. Never deploy malicious software without explicit authorisation.  

## 1. Overview <a name="overview"></a>
This project implements a sophisticated Windows malware with some evasion capabilities and a command-and-control (C2) server.

## 2. Setup Requirements <a name="setup-requirements"></a>
- Recommend to use VS Code IDE, and follow a steps from this link [GCC with MinGW](https://code.visualstudio.com/docs/cpp/config-mingw).
- To compile the malware, you need to install MinGW-w64 compiler for 32-bit Windows, Open **MSYS2 UCRT64** terminal and run ``pacman -S mingw-w64-i686-gcc`` and enter 'Yes'.
- Open **Edit environment variables** for your account, in your **User variables**, select the **Path** variable and then select **Edit**. Make sure you must have these inside path:
<p style="text-align: center"><img src=image.png></p>

## 3. Malware <a name="malware"></a>
- The malware code is found under the 'client' directory 
- The malware is build/compile by ``bulid.bat`` file by runing `./bulid.bat` in the terminal will generate 'malware.exe'. 
- If require to change the code, eg. uncomment/comment the print statement to debug, you need to save changed file and run `bulid.bat`. 
- To run malware.exe, just simply double-click the malware.exe or `./malware.exe` in the terminal 

## 4. C2 Server <a name="c2-server"></a>
To run the server: 
- Require Python 3.6+ and Flask library by running the command on vs code terminal `pip install flask`
- To run the server, go to 'c2_server' directory and run `py .\app.py`
- Then ctrl+click on http://127.0.0.1:5000 on the terminal 
- To know how the use c2 server, please watch the video demonstration on core. 

## 5. Evasion Techniques Implemented <a name="evasion-techniques-implemented"></a>
### Implemented Defenses

| Technique | Implementation Details | Source File |
|-----------|------------------------|-------------|
| Encrypted C2 Communications | XOR encryption with key rotation (0xAC initial key)| **c2.c** |
| Polymorphic Code | Runtime XOR encryption of function bodies with rotating key | **completion.c** |
| String Obfuscation | Critical strings encrypted at rest and decrypted in memory | **completion.c** |
| Anti-Debugging | Hardware breakpoints, RDTSC timing checks | **evasion.c** |
| Anti-Analysis Tool Detection | Process enumeration for security tools (IDA, Wireshark, etc.) | **completion.c** |
| VM Detection | Hypervisor bit check, VM MAC addresses | **evasion.c** |
| Sandbox Evasion | Uptime, RAM, CPU core, and user activity checks | **evasion.c** |
| Persistence | Registry Run keys + Windows Service | **completion.c** |
| Process Injection | Injection into explorer.exe using CreateRemoteThread | **completion.c** |
| Beacon Jitter | ±25% random variation in beacon interval | **completion.c** |
| Anti-Dumping | PE header zeroing | **completion.c** |
| Domain Generation Algorithm | Time-based domain generation framework (hardcoded)| **evasion.c**|
| Stealth Storage | Alternate Data Streams (ADS) for log storage | **keylogger.c** |

### Testing Results on FlareVM
| Component | Status | Notes |
|-----------|--------|-------|
| Client Registration | ✔️ | Appears in C2 dashboard within 5s |
| Keylogging | ✔️ | Captures basic keystrokes but the typing input are slow in the VM |
| Command Execution | ✔️ | All commands verified via debug output |
| Log Exfiltration | ✔️ | Logs appear in C2 within 10s interval |
| Retry Mechanism | ✔️ | Trying to exfiltrate without stopping |
| Anti-Debugging | ✔️ | Detects x32dbg and ollydbg |
| VM Detection | ✔️ | Detect FlareVM when running exe |
| ADS Logging | ✔️ | Hide in the streams on `legit.txt` in `%temp%` directory |
| Sandbox Evasion | ✔️ | Tested on [hybrid-analysis](https://www.hybrid-analysis.com/) resulting 63/100 on Falcon Sandbox Reports |
| Persistence (Reg) | ✔️ | Survives reboot via registry. Found in `Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and autostart work |
| Persistence (Svc) | ❓ | Not sure it working because of privilege access|
| Process Injection | ❓ | Not sure it working |
| Network Evasion | ✔️ | Beacon interval varies ±25% affect Wireshark (time deltas) |
| Polymorphic Code | ❌ | Same hash. First hash: 749013666CC10DBEB7DD9C3F52546BC6 Second Hash: 749013666CC10DBEB7DD9C3F52546BC6 |
| Function Obfuscation | ❌ | Unable to Obfuscate "StartKeylogger", "BeaconToC2", "HandleCommand" in Ghidra |
| String Obfuscation | ❌ | Unable to Obfuscate "Windows-Update-Agent", "command", "upload" in strings |
| Anti-Dumping | ✔️ | Able to corrupted PE headers using PE-bear |
| DGA | ❌ | The c2 server is using fixed ip address 127.0.0.1, fail to implement |
| UPX | ✔️ | Using upx packer to avoid string analysis |

## 6. Known Bugs/Limitations <a name="known-limitations"></a>

1. **Keylogger**:
   * When the malware is running, the typing input are delay in the VM causing the system a bit lagging 

2. **Platform Support**:
   * Tested only on FlareVM 64 bit

3. **Tools**:
   * Have not test all the common analysis tools, only some

4. **Functional Limitations**:
   * GenerateDomain() - Domain Generation Algorithm (DGA) uses hardcoded IP because the server using fix IP (127.0.0.1)
   * ApplyPolymorphicMask() - Fail to polymorphic the code 
   * ObfuscateCriticalFunctions() - Fail to obfuscate function name 
   * ProcessInjection() - Not sure if it working 


## 7. Important Note
* Not all the completion method are used in the submission malware.exe. Some of the completion method is not working or stopped the malware running, so there will be two version of malware.exe in the submission. One (malware.exe) will not have vm detection and others to run in the VM, other malware (malware2.exe) will be vm detection, anti-debugging, anti-analysis and other enable. 