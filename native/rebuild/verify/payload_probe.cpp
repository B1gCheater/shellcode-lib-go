// Minimal C++ DLL used as a post-unload probe: it throws and catches inside its
// export. Loaded normally (LoadLibrary) AFTER a donut payload has run and
// unloaded, it verifies the host's C++ exception handling was left intact by the
// cleanup (IAT restored, stub freed, function table deregistered).
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    (void)h; (void)p;
    return TRUE;
}

extern "C" __declspec(dllexport) void Probe(void) {
    volatile int caught = 0;
    try {
        throw 7;
    } catch (int e) {
        caught = e;
    }
    printf("PROBE_CXX caught=%d\n", caught);
    fflush(stdout);
}