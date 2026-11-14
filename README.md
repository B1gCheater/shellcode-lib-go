# shellcode-lib-go

A Go library for converting native Windows PE images into position-independent
code. The API accepts bytes and returns bytes; applications own file handling,
command-line interfaces, and execution.

Derived from [Donut](https://github.com/TheWover/donut) by TheWover and Odzhan.
The embedded native loader contains modifications and is not byte-identical to
the upstream loader. This is not a drop-in replacement for the Windows loader.

## Requirements

- Go 1.21 or later.
- No third-party Go dependencies or cgo requirement.
- Generation can be built on Windows, Linux, and macOS. Generated code targets
  Windows x86 or x64; it is not executable on Linux or macOS.
- XPRESS generation requires Windows. LZNT1 generation is portable.

## Package API

The public package is `donut`.

| API | Purpose |
| --- | --- |
| `Inspect` | Read native PE type and architecture information. |
| `Compat` | Report known loader compatibility limitations. |
| `DefaultConfig` | Create a configuration for an input image. |
| `Build` | Generate output bytes from a configuration. |
| `Config.TruncatedFields` | Report values that exceed the encoded field widths. |

The exported types and fields are documented in the Go source. Introspection
helpers are retained for existing callers. No CLI or execution runner is included.

Supported inputs are native EXE and DLL images. Managed assemblies, scripts,
network staging, and the upstream original-entry-point option are not supported.
Compression supports uncompressed input, LZNT1, and Windows-host XPRESS; aPLib
generation is not implemented.

`DefaultConfig` retains the development library's existing defaults, including
its security-bypass policy and header handling. Review every configuration field
explicitly for your application; defaults are not a compatibility guarantee.
Parameter strings have fixed encoded limits and may be truncated. Inspect
`TruncatedFields` before treating generation as successful.

## Build

```text
go build ./...
go vet ./...
```

This distribution intentionally excludes tests, fixtures, examples, command-line
programs, execution helpers, and experimental artifacts. Consequently,
`go test ./...` here does not run the development project's regression suite.

## Compatibility and validation

The loader does not reproduce all operating-system loader services. In particular:

- Static TLS variables are not fully supported; running TLS callbacks does not
  establish full TLS compatibility.
- x86 C++ exception handling remains unsupported.
- Load-configuration metadata and DLL lifecycle notifications are not fully
  implemented. A compatibility report without blockers does not prove safe
  execution, unloading, or host-process isolation.
- Input headers and data must be treated as untrusted. Parsing and compatibility
  inspection do not establish that an image is safe to execute.
- Applications must validate their own dependencies, process-wide state,
  callbacks, and shutdown behavior.

In the development workspace, the current loader revision passed local Windows
x86/x64 regression checks, including a system-module lookup outside the mapped
image and a runner timeout check. A Color-Detector application also completed a
30-second shared-memory publication check, repeated process starts/stops, and
repeated diagnostic loads in one Python host with security bypass disabled.
These are local observations, not a cross-platform or long-duration certification.
The development tests are not included in this minimal distribution.

## Repository layout

```text
donut/                 Public API, PE inspection, encoding, compression, loaders
internal/ntcompress/   Windows compression support required by the library
native/                Native-loader source modification patch
go.mod                 Go module declaration
LICENSE                BSD 3-Clause license and upstream attribution
README.md              Project documentation
```

The generated loader arrays are in `donut/zz_loader_blobs_enhanced.go`.
`native/loader-enhance.patch` records the modifications against Donut 1.1; it is
included for provenance and maintenance, not as a caller-facing CLI. Regenerating
the arrays requires the upstream native sources and a compatible build toolchain.

## Publishing

The module path is `github.com/B1gCheater/shellcode-lib-go`.
Consumers import the public package as `github.com/B1gCheater/shellcode-lib-go/donut`.
Publish the repository under the same owner and repository name as the module path.

This is a minimal source distribution. The local validation described above is
not an independent certification of a stable release.

## License

BSD 3-Clause. See [LICENSE](LICENSE). Upstream notices and attribution are retained.
