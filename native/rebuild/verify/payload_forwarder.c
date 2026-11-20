// DLL whose only export is a forwarder to msvcrt.puts. Exercises the loader's
// run-time forwarder resolution: "RunIt" resolves through "msvcrt.puts", which
// prints the argument string the loader passes it.
//
// The forwarder itself is declared in payload_forwarder.def:
//   EXPORTS
//     RunIt=msvcrt.puts
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("PAYLOAD_FWD attach\n");
        fflush(stdout);
    }
    return TRUE;
}
