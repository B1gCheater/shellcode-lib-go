// Package donut generates position independent shellcode that loads a native PE
// module - an executable or a DLL built by C, C++, Rust, Go or any other toolkit
// that emits a conventional Windows image - in memory.
//
// The generator's bytes are donut's: for the same options and the same input, the
// prologue, the DONUT_INSTANCE and the module blob are exactly the bytes donut
// would have written. That property is enforced by the golden tests, which diff
// the loader-independent prefix of every case against reference shellcode from a
// donut binary built from the upstream source. The loader tail is the enhanced
// stub pair (see "The loader" below and README.md), which deliberately
// trades byte compatibility for fixes the stock stubs lacked, so full output is
// not byte comparable and the loader is proven by execution instead. Managed
// assemblies and scripts are outside the generated surface; see ErrManagedImage.
//
// The library performs no I/O and holds no global state. Everything the generator
// needs is passed in, and the result is returned as a byte slice:
//
//	data, err := os.ReadFile("payload.dll")
//	if err != nil {
//		return err
//	}
//
//	cfg := donut.DefaultConfig(data)
//	cfg.Arch = donut.ArchX64
//	cfg.Method = "RunIt"
//	cfg.Args = "--verbose"
//	pic, err := donut.Build(cfg)
//
// pic is the shellcode. Run it wherever you like: the package has no opinion and
// never touches the filesystem.
//
// The shellcode is Windows-only at run time (x86 or amd64), but the generator
// itself is portable. It builds and behaves identically on any host, because the
// instance structure is assembled into a byte slice at explicit offsets rather than
// through a Go struct.
//
// # The loader
//
// The loader stub appended after the instance is rebuilt from donut's loader
// sources with tools/loader-enhance.patch: static-CRT (/MT) payloads run, the
// re-mapped view keeps the address the relocations were applied at, x64 exception
// tables are registered (SEH works), x64 C++ exceptions are caught, and imports
// without a lookup table fall back to the IAT. DLLs get a faithful
// DLL_PROCESS_ATTACH/DETACH pair (a refusing DllMain aborts the load), forwarded
// exports are resolved through their target module, and x64 static TLS is
// registered through ntdll's LdrpHandleTlsData (best-effort). There is no loader
// selection knob; README.md records what was changed and what still cannot work
// (x86 static TLS, 32-bit C++ exceptions).
//
// # Licence
//
// This package is a port of donut, which is BSD 3-Clause licensed:
//
//	Copyright (c) 2019-2020, TheWover, Odzhan. All rights reserved.
//
// The embedded loader stubs in zz_loader_blobs_enhanced.go are donut's generated
// artifacts and carry the same terms. See LICENSE.
package donut

import "errors"

// Target architectures. ArchX84 carries both loader stubs and is the default; the
// single-architecture options are about 11 KB smaller.
const (
	ArchX86 = 1
	ArchX64 = 2
	ArchX84 = 3
)

// Module types this package generates. The values are donut's, and the two it does
// not generate are documented below rather than exported, because the loader stubs
// still dispatch on them and DONUT_MODULE still carries the field at that offset.
const (
	ModuleDLL = 3 // native DLL: DllMain, then optionally a named export
	ModuleEXE = 4 // native EXE: the image entry point
)

// The remaining DONUT_MODULE type values are part of the wire protocol but are
// never produced here. They are unexported so callers cannot pass them, and named
// so that anyone reading generated shellcode can decode it.
const (
	moduleNetDLL = 1 // .NET assembly with a class and method
	moduleNetEXE = 2 // .NET assembly entry point
	moduleVBS    = 5 // VBScript
	moduleJS     = 6 // JScript
)

// InstanceEmbed is the only instance type this package produces. donut also
// defines HTTP and DNS staging; the loader stubs understand the former and the
// DNS path is dead code upstream, and neither is generated here.
const (
	InstanceEmbed = 1
	instanceHTTP  = 2
	instanceDNS   = 3
)

// Entropy levels control how much random material is used.
//
// EntropyNone   no randomisation, no encryption; fields are readable in the clear
// EntropyRandom randomises the EXE command-line placeholder, no encryption
// EntropyDefault that placeholder plus Chaskey encryption of the instance
const (
	EntropyNone    = 1
	EntropyRandom  = 2
	EntropyDefault = 3
)

// Bypass levels control what happens when the AMSI, WLDP and ETW patches fail. The
// patching itself lives in the loader stubs; see README.md.
const (
	BypassNone     = 1
	BypassAbort    = 2
	BypassContinue = 3
)

// HeadersOverwrite zeroes the mapped image's PE headers, removing the MZ/PE
// signature from memory. HeadersKeep leaves them in place for modules that read
// their own headers.
const (
	HeadersOverwrite = 1
	HeadersKeep      = 2
)

// Exit behaviour after the module returns.
//
// donut also defines value 3, "block forever rather than exit or clean up". That
// branch runs before the loader's erase-and-free step, so its only effect is to
// leave the instance unscrubbed in memory; it is deliberately not accepted.
const (
	ExitThread  = 1 // return to the caller, which calls RtlExitUserThread
	ExitProcess = 2 // call RtlExitUserProcess
)

// Payload compression engines for DONUT_MODULE.compress, matching donut's
// wire values. CompressNone is the default. CompressLZNT1 and CompressAPLib go
// through portable pure-Go encoders (lznt1.go, aplib.go), so they generate —
// byte-identically — on every host; CompressXpress has no portable encoder and
// is answered by ntdll's RtlCompressBuffer on Windows and refused elsewhere.
// Either way the loader stub expands the result with RtlDecompressBuffer
// (LZNT1/XPRESS) or aP_depack (aPLib) on the target, so the wire format is
// exactly donut's.
const (
	CompressNone   = 1
	CompressAPLib  = 2
	CompressLZNT1  = 3
	CompressXpress = 4
)

// Field widths inside DONUT_MODULE. These are donut's own limits, measured against
// a donut binary rather than inferred. An over-long Args is truncated by Build
// exactly as the C generator truncates it, so it does not fail but does lose bytes;
// Config.TruncatedFields reports which fields will be cut before that happens.
// Method is the exception: an over-long export name is refused with
// ErrMethodNameTooLong, because the loader resolves the export by the stored
// (truncated) name and would otherwise build shellcode that cannot find it.
const (
	// MaxNameLen is the width donut gives a DLL export name.
	MaxNameLen = maxName - 1
	// MaxArgsLen is the width donut appends for parameters. An unmanaged EXE
	// reserves five bytes at the front for its command-line placeholder, so that
	// field ends up 255 bytes wide while carrying only 250 bytes of caller text.
	MaxArgsLen = argsMaxLen
)

// Errors returned by this package. Each failure wraps exactly one of these, so
// callers can branch with errors.Is. The names track donut's DONUT_ERROR_* codes
// where the concept carries over, for anyone porting from the C API.
var (
	// ErrEmptyInput means Config.Payload was nil or zero length.
	ErrEmptyInput = errors.New("donut: payload is empty")
	// ErrFileInvalid means the payload is not a valid PE image. Scripts and data
	// files land here.
	ErrFileInvalid = errors.New("donut: payload is not a valid PE image")
	// ErrManagedImage means the payload is a .NET assembly. The package generates
	// shellcode for native images only; use Inspect to filter candidates.
	ErrManagedImage = errors.New("donut: managed (.NET) assemblies are not supported")
	// ErrInvalidType means Config.ModuleType contradicts the PE headers, or names
	// a module kind this package does not generate.
	ErrInvalidType = errors.New("donut: module type does not match the image")
	// ErrArchMismatch means the requested target cannot host the image, such as an
	// x86 target for an x64 DLL.
	ErrArchMismatch = errors.New("donut: target architecture cannot support the payload")
	// ErrDLLFunction means the named export is not in the DLL's export table. The
	// name is matched exactly, so this also catches a case error.
	ErrDLLFunction = errors.New("donut: the named DLL export does not exist (names are case sensitive)")
	// ErrDLLParam means parameters were given for a DLL without an export to
	// receive them.
	ErrDLLParam = errors.New("donut: parameters for a DLL require Method to name an export")
	// ErrMethodNameTooLong means Config.Method exceeds the encoded field width.
	// The loader resolves the export by the stored (truncated) name, so a name
	// that does not fit would build but never resolve on the target; Build refuses
	// it instead.
	ErrMethodNameTooLong = errors.New("donut: DLL export name exceeds the encoded field width")
	// ErrForwardedExport named a forwarded export whose RVA is a "DLL.Func"
	// string, not code. It is retained for API compatibility but is no longer
	// returned: the loader now resolves forwarders through their target module at
	// run time (see Compat's CodeForwardedExport).
	ErrForwardedExport = errors.New("donut: the named DLL export is a forwarder, not callable by address")

	// ErrIncompatiblePayload is returned by Build when Config.Strict is set and
	// Compat found a blocker. The message lists the blockers verbatim.
	ErrIncompatiblePayload = errors.New("donut: payload is not handled correctly by the loader")

	ErrInvalidArch    = errors.New("donut: invalid architecture")
	ErrInvalidEntropy = errors.New("donut: invalid entropy level")
	ErrInvalidBypass  = errors.New("donut: invalid bypass level")
	ErrInvalidHeaders = errors.New("donut: invalid PE header option")
	ErrInvalidExit    = errors.New("donut: invalid exit option")
	ErrRandom         = errors.New("donut: could not generate random values")
	// ErrCompression reports a compression request this package cannot serve:
	// an unknown engine, or a supported engine on a host where the generator
	// cannot run (XPRESS is Windows-only; LZNT1 and aPLib are portable).
	ErrCompression = errors.New("donut: compression failed")
	// ErrInvalidKeyMaterial reports pinned key material the loader could
	// not verify, such as a signature containing a zero byte.
	ErrInvalidKeyMaterial = errors.New("donut: invalid pinned key material")
)
