// DLL with NO entry point (AddressOfEntryPoint == 0), built with -nostdlib
// -Wl,--entry,0. Only an exported function. Verifies enhancement #4: the loader
// must skip DllMain and still call the named export.
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void RunIt(void) {
    printf("PAYLOAD_NOENTRY run\n");
    fflush(stdout);
}