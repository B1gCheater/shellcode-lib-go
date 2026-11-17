// Non-interactive shellcode runner for behavioural verification.
//
// Reads a raw shellcode blob from argv[1], maps it RWX, calls it, and prints
// RUNNER_OK if control returns. Designed to be launched as an isolated child
// process with a timeout so a faulty loader cannot take down the harness.
//
// This is a local test artefact; it performs no network or filesystem writes
// beyond reading the blob it is given.

#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: runner <shellcode.bin>\n");
        return 2;
    }

    HANDLE hf = CreateFileA(argv[1], GENERIC_READ, 0, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "RUNNER_ERR open %lu\n", GetLastError());
        return 2;
    }
    DWORD len = GetFileSize(hf, NULL);
    if (len == 0 || len == INVALID_FILE_SIZE) {
        fprintf(stderr, "RUNNER_ERR size\n");
        CloseHandle(hf);
        return 2;
    }
    BYTE *buf = (BYTE *)malloc(len);
    DWORD rd = 0;
    BOOL ok = ReadFile(hf, buf, len, &rd, NULL);
    CloseHandle(hf);
    if (!ok || rd != len) {
        fprintf(stderr, "RUNNER_ERR read\n");
        free(buf);
        return 2;
    }

    LPVOID cs = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (cs == NULL) {
        fprintf(stderr, "RUNNER_ERR alloc %lu\n", GetLastError());
        free(buf);
        return 2;
    }
    memcpy(cs, buf, len);
    free(buf);

    fflush(stdout);
    fflush(stderr);

    void (*fn)(void) = (void (*)(void))cs;
    fn();

    printf("RUNNER_OK\n");
    fflush(stdout);
    return 0;
}