# Build the behavioural-verification artefacts.
# Run from anywhere; paths are anchored to this script's location.
$ErrorActionPreference = "Stop"
$gcc = "C:\software\gcc\bin\gcc.exe"
$here = $PSScriptRoot                 # native/rebuild/verify
$work = Join-Path $here "..\work"     # native/rebuild/work (patched source)
$rebuild = Join-Path $here ".."       # native/rebuild

$common = @("-DBYPASS_AMSI_B","-DBYPASS_WLDP_A","-DBYPASS_ETW_B",
            "-fno-toplevel-reorder","-fno-builtin","-fpack-struct=8","-fPIC","-Os","-nostdlib",
            "-mno-stack-arg-probe")
$srcs = @("loader/loader.c","loader/depack.c","loader/clib.c","hash.c","encrypt.c","intrinsics.c")

Push-Location $work
try {
    # x64 loader (get_pc is a no-op on x64, not needed)
    & $gcc @common $srcs -I include -o loader64_v.exe
    if ($LASTEXITCODE -ne 0) { throw "x64 loader build failed" }
    & ".\exe2h.exe" loader64_v.exe | Out-Null

    # x86 loader: get_pc is already included by loader.c (do not add getpc.c again)
    & $gcc -m32 @common $srcs -I include -o loader32_v.exe
    if ($LASTEXITCODE -ne 0) { throw "x86 loader build failed" }
    & ".\exe2h.exe" loader32_v.exe | Out-Null
} finally { Pop-Location }

# Extract raw .text blobs (strip the Go wrapper -> pure bytes) via a tiny helper.
Push-Location $here
try {
    & go build -o blob2bin.exe blob2bin.go
    if ($LASTEXITCODE -ne 0) { throw "blob2bin build failed" }
    & ".\blob2bin.exe" (Join-Path $work "loader64_v_exe_x64.go") (Join-Path $here "loader64_os_exe_x64.bin")
    if ($LASTEXITCODE -ne 0) { throw "x64 blob conversion failed" }
    & ".\blob2bin.exe" (Join-Path $work "loader32_v_exe_x86.go") (Join-Path $here "loader32_os_exe_x86.bin")
    if ($LASTEXITCODE -ne 0) { throw "x86 blob conversion failed" }
} finally { Pop-Location }

Push-Location $here
try {
    # runners: x64 shellcode needs a 64-bit host; x86 shellcode needs a 32-bit
    # host (a WOW64 process is not a supported host for the x86 loader).
    & $gcc runner.c -o runner.exe
    if ($LASTEXITCODE -ne 0) { throw "runner build failed" }
    & $gcc -m32 runner.c -o runner32.exe
    if ($LASTEXITCODE -ne 0) { throw "runner32 build failed" }

    # benign payloads, both architectures, dynamic CRT
    & $gcc payload_exe.c -o payload_exe64.exe
    if ($LASTEXITCODE -ne 0) { throw "exe64 build failed" }
    & $gcc -m32 payload_exe.c -o payload_exe32.exe
    if ($LASTEXITCODE -ne 0) { throw "exe32 build failed" }
    & $gcc -shared payload_dll.c -o payload_dll64.dll
    if ($LASTEXITCODE -ne 0) { throw "dll64 build failed" }
    & $gcc -m32 -shared payload_dll.c -o payload_dll32.dll
    if ($LASTEXITCODE -ne 0) { throw "dll32 build failed" }

    # generator
    & go build -o gen.exe "./gen"
    if ($LASTEXITCODE -ne 0) { throw "gen build failed" }
} finally { Pop-Location }

Write-Output "verification artefacts built OK"