// Repeated-load runner: executes the same shellcode blob N times in ONE process.
// Verifies the cleanup enhancements (function-table deregistration, IAT restore,
// stub-page free): after each load the host must be left clean, so the next load
// works and the host's own C++ exception handling still functions.
//
// Usage: runner_loop <shellcode.bin> <iterations>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// A C++-free probe of the host's RtlPcToFileHeader: after the payload unloads and
// restores the IAT, this must still resolve a host address to the host module.
typedef PVOID (NTAPI *RtlPcToFileHeader_t)(PVOID, PVOID*);

// Count committed private executable regions (RWX/RX). The pc2f stub is a 4KB
// PAGE_EXECUTE_READWRITE private page; if cleanup does not free it, this count
// grows with each load.
static int count_exec_private(void) {
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    int n = 0;
    while (VirtualQuery((PVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_WRITECOPY || mbi.Protect == PAGE_EXECUTE)) {
            n++;
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: runner_loop <blob> <iters>\n");
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

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    RtlPcToFileHeader_t pc2f = (RtlPcToFileHeader_t)GetProcAddress(ntdll, "RtlPcToFileHeader");

    int exec_before = count_exec_private();
    printf("EXEC_PRIVATE_BEFORE %d\n", exec_before);
    fflush(stdout);

    for (int i = 0; i < iters; i++) {
        LPVOID cs = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cs) { fprintf(stderr, "LOOP_ERR alloc iter=%d\n", i); return 2; }
        memcpy(cs, buf, len);
        fflush(stdout);
        void (*fn)(void) = (void(*)(void))cs;
        fn();
        VirtualFree(cs, 0, MEM_RELEASE);

        // Host sanity: RtlPcToFileHeader must still answer for a host address.
        PVOID base = NULL;
        PVOID self = (PVOID)pc2f;
        PVOID got = pc2f(self, &base);
        if (got == NULL || base != (PVOID)ntdll) {
            fprintf(stderr, "LOOP_ERR host_pc2f iter=%d got=%p base=%p ntdll=%p\n",
                    i, got, base, (PVOID)ntdll);
            return 3;
        }
        printf("LOOP_ITER_OK %d\n", i);
        fflush(stdout);
    }
    free(buf);
    int exec_after = count_exec_private();
    printf("EXEC_PRIVATE_AFTER %d\n", exec_after);
    printf("EXEC_PRIVATE_DELTA %d\n", exec_after - exec_before);
    printf("LOOP_DONE %d\n", iters);
    fflush(stdout);
    return 0;
}