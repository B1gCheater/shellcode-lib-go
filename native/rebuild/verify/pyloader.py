"""Standalone Python loader: runs a shellcode blob produced by the library.

Independent of the Go harness — uses only ctypes + the Win32 API. Must be run
with a Python interpreter whose bitness matches the shellcode (64-bit Python for
x64 shellcode, 32-bit for x86).

Usage: python pyloader.py <shellcode.bin>
"""
import ctypes
import sys
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
kernel32.RtlMoveMemory.restype = ctypes.c_void_p
kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


def main():
    if len(sys.argv) != 2:
        print("usage: python pyloader.py <shellcode.bin>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        code = f.read()
    if not code:
        print("PYLOADER_ERR empty", file=sys.stderr)
        return 2

    ptr = kernel32.VirtualAlloc(None, len(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        print(f"PYLOADER_ERR alloc {ctypes.get_last_error()}", file=sys.stderr)
        return 2
    kernel32.RtlMoveMemory(ptr, code, len(code))

    print(f"PYLOADER_RUNNING {len(code)} bytes", flush=True)
    fn = ctypes.CFUNCTYPE(None)(ptr)
    fn()
    print("PYLOADER_RETURNED", flush=True)

    kernel32.VirtualFree(ptr, 0, MEM_RELEASE)
    return 0


if __name__ == "__main__":
    sys.exit(main())