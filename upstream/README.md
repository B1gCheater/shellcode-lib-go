# Upstream archive

Reference material kept inside this repository so the project can be rebuilt and
audited without depending on an external checkout. **Nothing here is compiled,
imported, or tested by the library.** Each subdirectory carries its own `go.mod`
so the Go tool treats it as a separate module and the parent ignores the subtree.

Verified at archive time: every file under `donut-1.02/` was compared against the
source checkout with SHA-256 — 82 files, 0 mismatches.

## Layout

```
upstream/
  donut-1.02/            pristine upstream donut (v1.02), unmodified
  enhanced-loader-src/   the enhanced loader source snapshot + build helpers
```

## donut-1.02/ — pristine upstream

Copied byte-for-byte from a `donut-master` checkout (version per
`version-release-notes.txt` / `CHANGELOG.md`: v1.02). Upstream is BSD 3-Clause,
Copyright (c) 2019, TheWover, Odzhan; `LICENSE` is retained in this directory as
required by clause 1.

Why each part matters:

| Path | Why it is archived |
| --- | --- |
| `loader_exe_x86.h`, `loader_exe_x64.h` | **The original authors' stock loader stubs.** The authoritative pre-enhancement bytes, in C form. |
| `loader_exe_x86.go`, `loader_exe_x64.go` | The same stock stubs as Go arrays (`package donut`). This is why the nested `go.mod` is required — without it these files would be compiled into our own `donut` package. |
| `loader/` | Native loader sources. `inmem_pe.c` is the file our patch modifies; `loader.c` includes it. `exe2h/` is the tool that extracts `.text` into the arrays. |
| `include/` | Headers the loader and generator compile against, including `donut.h` (the `DONUT_INSTANCE` / `DONUT_MODULE` layouts our `instance.go` reproduces). |
| `lib/` | aPLib static libraries (`aplib32/64.lib/.a`). Needed only to build upstream's own generator; our library implements aPLib packing in portable Go (`donut/aplib.go`) and does not use these binaries. |
| `donut.c`, `hash.c`, `encrypt.c`, `format.c`, `donutmodule.c` | Upstream generator, MARU hash, Chaskey cipher, output formats. The reference for our Go port's byte compatibility. |
| `Makefile*`, `Dockerfile` | Upstream build recipes. `Makefile.msvc` shows the original `-Os` / `-Zp8` flags; `Makefile.mingw` shows the MinGW equivalents. |
| `README.md`, `CHANGELOG.md`, `version-release-notes.txt` | Provenance: what upstream version this is and what it claimed to support. |

The stock stubs are kept for comparison only. The library embeds the **enhanced**
stubs in `donut/zz_loader_blobs_enhanced.go`, not these.

## enhanced-loader-src/ — our enhancement snapshot

| File | What it is |
| --- | --- |
| `loader/inmem_pe.c` | The enhanced loader source: upstream v1.02 plus `native/loader-enhance.patch`, plus the later enhancements (entry-less DLL support, `RtlDeleteFunctionTable` on cleanup, IAT hook restore, stub-page free, `DLL_PROCESS_DETACH` delivery, `DllMain` return-value check, TLS detach callbacks, run-time forwarder resolution, and x64 static-TLS registration via `LdrpHandleTlsData`). |
| `intrinsics.c` | Build shim. Modern GCC lowers large struct copies to `memcpy`/`memset` even at `-Os`; under `-nostdlib` those are undefined. This provides byte-loop implementations. Compile with `-fno-builtin` so GCC does not rewrite the bodies into recursive calls. |
| `build.ps1` | The verified rebuild + verification-artefact script (also lives in `native/rebuild/verify/`). |
| `blobgen.go.txt` | The generator for `donut/zz_loader_blobs_enhanced.go`. Stored with a `.txt` suffix so it is inert; the live copy is `native/rebuild/blobgen/main.go`. |

This snapshot is a convenience. The canonical, reproducible path is
**pristine source + patch**, not this copy — see below.

## Rebuilding the enhanced loader

The archive plus the archived patch is sufficient; no external checkout needed.

1. Copy `donut-1.02/` to a scratch directory (never modify the archive).
2. Apply `native/loader-enhance.patch` from that scratch directory:
   `git apply <path-to>/native/loader-enhance.patch`
   (verified to apply cleanly to this exact upstream revision).
3. Add `enhanced-loader-src/intrinsics.c` to the scratch directory.
4. Build both architectures. Flags that matter: `-Os` (size — `-O0` roughly
   doubles `.text`), `-fpack-struct=8` (instance layout), `-fno-toplevel-reorder`
   (entry must stay first), `-fno-builtin`, `-nostdlib`, `-mno-stack-arg-probe`
   (large stack frames otherwise reference `___chkstk_ms`).

   ```
   gcc [-m32] -DBYPASS_AMSI_B -DBYPASS_WLDP_A -DBYPASS_ETW_B \
       -fno-toplevel-reorder -fno-builtin -fpack-struct=8 -fPIC -Os -nostdlib \
       -mno-stack-arg-probe \
       loader/loader.c loader/depack.c loader/clib.c hash.c encrypt.c intrinsics.c \
       -I include -o loader.exe
   ```

   Do **not** add `loader/getpc.c` explicitly — `loader.c` already includes it,
   and adding it again causes a duplicate `get_pc` definition.
5. Extract `.text` with `loader/exe2h/exe2h.c` (build it first). Confirm the entry
   point equals the `.text` start, and that `.text` has no relocations against
   `.rdata` — the shellcode ships `.text` only.
6. Regenerate the Go arrays with `blobgen`, then run the verification suites in
   `native/rebuild/` before trusting the result.

Toolchain used for the currently embedded blobs: MinGW-w64 GCC 16.2.0
(`x86_64-w64-mingw32`, with 32-bit multilib).

## Caveats

- Rebuilt blobs are **not byte-identical** to a different toolchain's output.
  Behaviour was verified equivalent by execution (see `native/rebuild/`), not by
  byte comparison. Always re-run those suites after a rebuild.
- The archive is a frozen snapshot. It does not track upstream; if upstream
  changes, re-archive deliberately and re-verify the patch still applies.
- `lib/*.lib` and `lib/*.a` are third-party (aPLib) binaries, included for
  upstream build completeness. They are not used by this library.