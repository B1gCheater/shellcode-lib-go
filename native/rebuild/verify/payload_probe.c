// C probe DLL (no C++ runtime, so it loads cleanly under a manual-mapping host).
// Its export checks the host's RtlPcToFileHeader: after a donut payload unloads,
// the IAT must be restored so this resolves a host address to the host module.
// A dangling hook would return NULL or the freed stub's answer.
#include <windows.h>
#include <stdio.h>

typedef PVOID (NTAPI *RtlPcToFileHeader_t)(PVOID, PVOID*);

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    (void)h; (void)p;
    return TRUE;
}

__declspec(dllexport) void Probe(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlPcToFileHeader_t pc2f = (RtlPcToFileHeader_t)GetProcAddress(ntdll, "RtlPcToFileHeader");
    PVOID base = NULL;
    // Ask about an address inside ntdll itself.
    PVOID got = pc2f((PVOID)pc2f, &base);
    if (got != NULL && base == (PVOID)ntdll) {
        printf("PROBE_PC2F ok\n");
    } else {
        printf("PROBE_PC2F BAD got=%p base=%p ntdll=%p\n", got, base, (PVOID)ntdll);
    }
    fflush(stdout);
}