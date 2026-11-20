// DLL with a static TLS variable. Verifies the loader's LdrpHandleTlsData
// registration: the variable must read its initial value after manual mapping
// rather than another module's slot. The export checks the value on the loading
// thread AND on a worker thread it creates, so the test covers both the
// current-thread template copy and the LdrpTlsList registration that provisions
// threads created later.
//
// Uses __thread (GCC's keyword) rather than __declspec(thread): this MinGW build
// ignores the declspec form.
#include <windows.h>
#include <stdio.h>

__thread int tls_magic = 0x12345678;

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    if (tls_magic == 0x12345678) {
        printf("PAYLOAD_TLS worker ok\n");
    } else {
        printf("PAYLOAD_TLS worker BAD got=0x%x want=0x12345678\n", tls_magic);
    }
    fflush(stdout);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("PAYLOAD_TLS attach tls_magic=0x%x\n", tls_magic);
        fflush(stdout);
    }
    return TRUE;
}

__declspec(dllexport) void RunIt(void) {
    if (tls_magic == 0x12345678) {
        printf("PAYLOAD_TLS run ok\n");
    } else {
        printf("PAYLOAD_TLS run BAD got=0x%x want=0x12345678\n", tls_magic);
    }

    HANDLE h = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (h != NULL) {
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
    }
    fflush(stdout);
}
