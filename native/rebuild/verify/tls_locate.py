# Maintenance helper: re-derive the LdrpHandleTlsData byte signature on a new
# Windows build.
#
# The loader locates ntdll's unexported LdrpHandleTlsData by a hardcoded prologue
# signature (see inmem_pe.c: fill_ldrp_tls_pattern). That signature is tied to a
# specific Windows build and must be refreshed when ntdll changes. This script
# reproduces the derivation:
#
#   1. Locate the ASCII string "LdrpHandleTlsData" in ntdll's .rdata. It is the
#      name of the function's __except filter, so it survives across builds.
#   2. Find the RIP-relative LEA that references that string (inside the filter).
#   3. The filter and LdrpHandleTlsData itself live near each other in .text; the
#      function has a stack-cookie prologue that starts with the bytes below.
#
# Run:  python tls_locate.py   (prints the string VA, the LEA VA, and a suggested
#                               prologue signature for the current build)
import struct

path = r"C:\Windows\System32\ntdll.dll"
data = open(path, "rb").read()

pe = struct.unpack_from("<I", data, 0x3C)[0]
fh = pe + 4
nsect = struct.unpack_from("<H", data, fh + 2)[0]
optsize = struct.unpack_from("<H", data, fh + 16)[0]
opt = pe + 24
is64 = struct.unpack_from("<H", data, opt)[0] == 0x20b
ib = struct.unpack_from("<Q" if is64 else "<I", data, opt + 0x18)[0]

secs = []
for i in range(nsect):
    o = opt + optsize + i * 40
    name = data[o:o+8].rstrip(b"\0").decode("latin1")
    vsz, va, rsz, roff = struct.unpack_from("<IIII", data, o + 8)
    secs.append((name, va, vsz, roff, rsz))

def off2rva(off):
    for name, va, vsz, roff, rsz in secs:
        if roff <= off < roff + rsz:
            return va + (off - roff)
    return None

idx = data.find(b"LdrpHandleTlsData\0")
srva = off2rva(idx)
sva = ib + srva
print(f"string VA {sva:#x}")

# find the LEA referencing the string
for i in range(len(data) - 7):
    if data[i] in (0x48, 0x4C) and data[i+1] == 0x8D:
        insn = off2rva(i)
        if insn is None:
            continue
        disp = struct.unpack_from("<i", data, i+3)[0]
        if ib + insn + 7 + disp == sva:
            print(f"LEA inside filter at VA {ib+insn:#x}")
            # walk back to the filter start for reference
            j = i
            while j > 0 and data[j] not in (0xCC, 0xC3):
                j -= 1
            print(f"filter (approx) VA {ib+off2rva(j):#x}")
            break

# The real function is found by its stack-cookie prologue; scan for a candidate
# unique prefix. Print the first ~28 bytes of every 48 89 5C 24 10 prologue so a
# maintainer can pick a unique one for fill_ldrp_tls_pattern.
print("candidate prologues (48 89 5c 24 10 ...):")
i = 0
while True:
    p = data.find(b"\x48\x89\x5c\x24\x10", i)
    if p == -1:
        break
    rva = off2rva(p)
    if rva is not None:
        print(f"  VA {ib+rva:#x}: {data[p:p+28].hex(' ')}")
    i = p + 1
