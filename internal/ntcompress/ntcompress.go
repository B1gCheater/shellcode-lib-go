//go:build windows

// Package ntcompress wraps the ntdll compression entry points the loader uses,
// in pure Go. No cgo and no C toolchain are required: the three functions are
// plain stdcall exports and are reached through syscall.NewLazyDLL.
//
// Compress and LoaderFormat support Windows-host XPRESS generation in the
// public donut package. Round-trip helpers are retained for internal diagnostics.
package ntcompress

import (
	"fmt"
	"syscall"
	"unsafe"
)

// NT status codes are 32-bit; STATUS_SUCCESS is zero.
const (
	// CompressionEngineMaximum is ORed into a format by the loader to request
	// the strongest engine. It is 0x100.
	CompressionEngineMaximum = 0x100

	// The COMPRESSION_FORMAT_* values, as reported by this host rather than
	// assumed from a header: see Probe.
	FormatLZNT1      = 0x0002
	FormatXpress     = 0x0003
	FormatXpressHuff = 0x0004
)

var (
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	procGetWorkSpaceSize = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	procCompressBuffer   = ntdll.NewProc("RtlCompressBuffer")
	procDecompressBuffer = ntdll.NewProc("RtlDecompressBuffer")
)

// Result reports what one format value did on this machine.
type Result struct {
	Format           uint16
	WorkSpaceSize    uint32
	MaxWorkSpaceReq  uint32
	Compressed       int
	CompressStatus   error
	Decompressed     int
	DecompressStatus error
	RoundTrip        bool
}

// String renders the result as one table row.
func (r Result) String() string {
	fail := func(err error) string {
		if err == nil {
			return "ok"
		}
		return fmt.Sprintf("0x%08X", uint32(err.(syscall.Errno)))
	}
	return fmt.Sprintf("0x%04X  ws=%-8d compress=%-10s decompress=%-10s roundtrip=%v",
		r.Format, r.WorkSpaceSize, fail(r.CompressStatus), fail(r.DecompressStatus), r.RoundTrip)
}

// WorkSpaceSize returns the workspace and maximum-required sizes for a format.
// The NT entry points report status in the first return value, so the errno from
// Call is not inspected.
func WorkSpaceSize(format uint16) (ws, max uint32, err error) {
	r1, _, _ := procGetWorkSpaceSize.Call(
		uintptr(format),
		uintptr(unsafe.Pointer(&ws)),
		uintptr(unsafe.Pointer(&max)))
	if r1 != 0 {
		return 0, 0, syscall.Errno(r1)
	}
	return ws, max, nil
}

// Compress compresses src with the given format. The workspace's first four
// bytes must hold its own size, which Windows checks.
func Compress(format uint16, src []byte) ([]byte, error) {
	ws, _, err := WorkSpaceSize(format)
	if err != nil {
		return nil, fmt.Errorf("workspace size: %w", err)
	}
	workspace := make([]byte, ws)
	*(*uint32)(unsafe.Pointer(&workspace[0])) = uint32(len(workspace))

	// The compressed output can be slightly larger than the input for
	// incompressible data.
	out := make([]byte, len(src)+512)
	var final uint32
	r1, _, _ := procCompressBuffer.Call(
		uintptr(format),
		uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(ws),
		uintptr(unsafe.Pointer(&final)),
		uintptr(unsafe.Pointer(&workspace[0])))
	if r1 != 0 {
		return nil, syscall.Errno(r1)
	}
	return out[:final], nil
}

// Decompress expands a stream produced by Compress.
func Decompress(format uint16, src []byte, hint int) ([]byte, error) {
	if hint < 1<<20 {
		hint = 1 << 20 // the loader sizes the buffer from the module header
	}
	out := make([]byte, hint)
	var final uint32
	r1, _, _ := procDecompressBuffer.Call(
		uintptr(format),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)),
		uintptr(unsafe.Pointer(&final)))
	if r1 != 0 {
		return nil, syscall.Errno(r1)
	}
	return out[:final], nil
}

// Probe runs a compress/decompress round trip for one format value.
func Probe(format uint16, data []byte) Result {
	r := Result{Format: format}
	ws, max, err := WorkSpaceSize(format)
	r.WorkSpaceSize, r.MaxWorkSpaceReq = ws, max
	if err != nil {
		r.CompressStatus, r.DecompressStatus = err, err
		return r
	}
	comp, err := Compress(format, data)
	if err != nil {
		r.CompressStatus = err
		return r
	}
	r.Compressed = len(comp)
	dec, err := Decompress(format, comp, len(data))
	if err != nil {
		r.DecompressStatus = err
		return r
	}
	r.Decompressed = len(dec)
	r.RoundTrip = len(dec) == len(data) && string(dec) == string(data)
	return r
}

// LoaderFormat maps a donut compression engine value to the format the loader
// passes to RtlDecompressBuffer: (engine - 1) with COMPRESSION_ENGINE_MAXIMUM
// ORed in. Engines 3 and 4 are the NT engines; 2 is aPLib, which the loader
// expands with its own unpacker.
func LoaderFormat(donutEngine int) uint16 {
	return uint16(donutEngine-1) | CompressionEngineMaximum
}
