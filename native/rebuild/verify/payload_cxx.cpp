// DLL that throws and catches a C++ exception inside its export. Verifies the
// x64 exception-table registration (RtlAddFunctionTable) and the C++ module-base
// hook (RtlPcToFileHeader): without them the catch is never matched and the
// exception escapes. Built with dynamic CRT (/MD equivalent) so vcruntime140 is
// loaded and its IAT is hooked.
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("PAYLOAD_CXX attach\n");
        fflush(stdout);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void RunIt(void) {
    volatile int caught = 0;
    try {
        throw 42;
    } catch (int e) {
        caught = e;
    }
    printf("PAYLOAD_CXX caught=%d\n", caught);
    fflush(stdout);
}