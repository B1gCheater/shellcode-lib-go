package donut

import "fmt"

// compressPayload compresses the payload with the requested donut engine.
//
// LZNT1 goes through the portable encoder in lznt1.go, so compressed
// generation works — and produces identical bytes — on every host. XPRESS has
// no portable encoder, so it is answered by ntdll's RtlCompressBuffer on
// Windows (the same call donut's own generator makes) and refused elsewhere.
// Either way the stream is what the loader stub's RtlDecompressBuffer path
// expects.
func compressPayload(engine int, data []byte) ([]byte, error) {
	switch engine {
	case CompressLZNT1:
		return compressLZNT1(data), nil
	case CompressXpress:
		return compressXpress(data)
	default:
		return nil, fmt.Errorf("%w: engine %d", ErrCompression, engine)
	}
}
