// Standalone C loader: reads a shellcode blob produced by the library and runs
// it. Independent of the Go harness — a plain Win32 executable.
//
// Usage: cloader <shellcode.bin>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: cloader <shellcode.bin>\n");
        return 2;
    }
    HANDLE hf = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CLOADER_ERR open %lu\n", GetLastError());
        return 2;
    }
    DWORD len = GetFileSize(hf, NULL);
    BYTE *buf = (BYTE*)malloc(len);
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, buf, len, &rd, NULL);
    CloseHandle(hf);
    if (!ok || rd != len) { fprintf(stderr, "CLOADER_ERR read\n"); free(buf); return 2; }

    LPVOID cs = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cs) { fprintf(stderr, "CLOADER_ERR alloc %lu\n", GetLastError()); free(buf); return 2; }
    memcpy(cs, buf, len);
    free(buf);

    printf("CLOADER_RUNNING %lu bytes\n", len);
    fflush(stdout);

    void (*fn)(void) = (void(*)(void))cs;
    fn();

    printf("CLOADER_RETURNED\n");
    fflush(stdout);
    VirtualFree(cs, 0, MEM_RELEASE);
    return 0;
}