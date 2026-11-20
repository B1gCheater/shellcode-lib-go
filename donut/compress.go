package donut

import "fmt"

// compressPayload compresses the payload with the requested donut engine.
//
// LZNT1 and aPLib go through the portable encoders in lznt1.go and aplib.go, so
// compressed generation works — and produces identical bytes — on every host.
// XPRESS has no portable encoder, so it is answered by ntdll's RtlCompressBuffer
// on Windows (the same call donut's own generator makes) and refused elsewhere.
// Either way the stream is what the loader stub's decompression path expects
// (RtlDecompressBuffer for LZNT1/XPRESS, aP_depack for aPLib).
func compressPayload(engine int, data []byte) ([]byte, error) {
	switch engine {
	case CompressLZNT1:
		return compressLZNT1(data), nil
	case CompressAPLib:
		return compressAPLib(data), nil
	case CompressXpress:
		return compressXpress(data)
	default:
		return nil, fmt.Errorf("%w: engine %d", ErrCompression, engine)
	}
}
