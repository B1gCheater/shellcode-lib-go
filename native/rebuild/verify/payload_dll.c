// Benign DLL payload: DllMain prints an attach marker; the exported RunIt prints
// a marker and a deterministic computation. Used to compare loader behaviour.
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("PAYLOAD_DLL attach\n");
        fflush(stdout);
    } else if (reason == DLL_PROCESS_DETACH) {
        printf("PAYLOAD_DLL detach\n");
        fflush(stdout);
    }
    return TRUE;
}

__declspec(dllexport) void RunIt(void) {
    volatile int sum = 0;
    for (int i = 1; i <= 100; i++) {
        sum += i;
    }
    printf("PAYLOAD_DLL run sum=%d\n", sum);
    fflush(stdout);
}