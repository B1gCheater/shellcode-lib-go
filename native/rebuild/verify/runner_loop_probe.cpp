// Repeated-load runner with a host C++ exception probe.
//
// Runs a donut shellcode blob N times in one process; after each load it
// LoadLibrary's a small C++ probe DLL and calls its export (which throws and
// catches). If the cleanup left the host's exception handling intact, every
// probe prints caught=7. A dangling IAT hook or stale function table would make
// the probe crash or fail to catch.
//
// Usage: runner_loop_probe <shellcode.bin> <iters> <probe.dll>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*ProbeFn)(void);

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: runner_loop_probe <blob> <iters> <probe.dll>\n");
        return 2;
    }
    int iters = atoi(argv[2]);
    if (iters < 1) iters = 1;

    HANDLE hf = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { fprintf(stderr, "LOOP_ERR open\n"); return 2; }
    DWORD len = GetFileSize(hf, NULL);
    BYTE *buf = (BYTE*)malloc(len);
    DWORD rd = 0;
    ReadFile(hf, buf, len, &rd, NULL);
    CloseHandle(hf);
    if (rd != len) { fprintf(stderr, "LOOP_ERR read\n"); return 2; }

    for (int i = 0; i < iters; i++) {
        LPVOID cs = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cs) { fprintf(stderr, "LOOP_ERR alloc iter=%d\n", i); return 2; }
        memcpy(cs, buf, len);
        fflush(stdout);
        void (*fn)(void) = (void(*)(void))cs;
        fn();
        VirtualFree(cs, 0, MEM_RELEASE);

        // Probe the host's C++ exception handling via a normally-loaded DLL.
        HMODULE probe = LoadLibraryA(argv[3]);
        if (!probe) { fprintf(stderr, "LOOP_ERR loadprobe iter=%d err=%lu\n", i, GetLastError()); return 3; }
        ProbeFn p = (ProbeFn)GetProcAddress(probe, "Probe");
        if (!p) { fprintf(stderr, "LOOP_ERR probeaddr iter=%d\n", i); FreeLibrary(probe); return 3; }
        p();
        FreeLibrary(probe);

        printf("LOOP_ITER_OK %d\n", i);
        fflush(stdout);
    }
    free(buf);
    printf("LOOP_DONE %d\n", iters);
    fflush(stdout);
    return 0;
}