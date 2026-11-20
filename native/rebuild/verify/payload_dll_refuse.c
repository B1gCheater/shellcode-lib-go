// DLL whose DllMain refuses DLL_PROCESS_ATTACH (returns FALSE). The loader must
// mirror the OS LoadLibrary contract: abort the load, do not call the export, and
// do not deliver a DLL_PROCESS_DETACH to a module that never attached.
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("PAYLOAD_REFUSE attach\n");
        fflush(stdout);
        return FALSE; // refuse to load
    }
    return TRUE;
}

__declspec(dllexport) void RunIt(void) {
    printf("PAYLOAD_REFUSE run\n"); // must NOT appear
    fflush(stdout);
}
