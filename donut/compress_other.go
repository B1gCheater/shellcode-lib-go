//go:build !windows

package donut

import "fmt"

// compressXpress reports instead of compressing: the XPRESS encoder lives
// behind ntdll, which does not exist here. LZNT1, the portable path, is what
// callers should use off Windows.
func compressXpress(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: engine %d requires a Windows host for now", ErrCompression, CompressXpress)
}
