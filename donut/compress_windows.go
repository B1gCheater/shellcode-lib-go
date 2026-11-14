//go:build windows

package donut

import (
	"fmt"

	"github.com/B1gCheater/shellcode-lib-go/internal/ntcompress"
)

// compressXpress compresses with ntdll's RtlCompressBuffer in XPRESS mode,
// which is also what donut's own generator calls. There is no portable XPRESS
// encoder yet, so this is the one engine that cannot generate everywhere.
func compressXpress(data []byte) ([]byte, error) {
	zdata, err := ntcompress.Compress(ntcompress.LoaderFormat(CompressXpress), data)
	if err != nil {
		return nil, fmt.Errorf("%w: engine %d: %v", ErrCompression, CompressXpress, err)
	}
	return zdata, nil
}
