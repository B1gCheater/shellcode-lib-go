package donut

import "encoding/binary"

// MARU-1 is donut's non-cryptographic hash, used to derive the API lookup
// hashes the loader resolves at run time, and to checksum the decryption
// signature.
//
// It is SPECK-64/128 in a Davies-Meyer style construction with an explicit
// 0x80 padding bit and a 64-bit bit-length field appended in the final block.
// Inputs are NUL-terminated strings and are truncated at 64 bytes.

const (
	maruBlockLen = 16
	maruMaxStr   = 64
)

// Maru hashes a string with the given initial value.
//
// The C implementation reads until a NUL byte or until 64 characters have been
// consumed, whichever comes first. Go strings are not NUL terminated, so the
// length check is the terminator for a full-length input and the two agree.
func Maru(input string, iv uint64) uint64 {
	var block [maruBlockLen]byte
	h := iv

	data := []byte(input)
	idx, length, end := 0, 0, false

	for !end {
		if length == len(data) || length == maruMaxStr {
			// Zero the remainder of the block and set the end bit.
			for i := idx; i < maruBlockLen; i++ {
				block[i] = 0
			}
			block[idx] = 0x80

			// If the length field does not fit in this block, flush it first.
			if idx >= maruBlockLen-4 {
				h ^= speck(block[:], h)
				block = [maruBlockLen]byte{}
			}
			binary.LittleEndian.PutUint32(block[maruBlockLen-4:], uint32(length)*8)
			idx = maruBlockLen
			end = true
		} else {
			block[idx] = data[length]
			idx++
			length++
		}

		if idx == maruBlockLen {
			h ^= speck(block[:], h)
			idx = 0
		}
	}
	return h
}

// speck implements SPECK-64/128: a 64-bit block, 128-bit key block cipher.
func speck(key []byte, plaintext uint64) uint64 {
	var k [4]uint32
	for i := 0; i < 4; i++ {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	w0 := uint32(plaintext)
	w1 := uint32(plaintext >> 32)

	for i := uint32(0); i < 27; i++ {
		w0 = (rotr32(w0, 8) + w1) ^ k[0]
		w1 = rotr32(w1, 29) ^ w0

		// Rotate the key schedule.
		t := k[3]
		k[3] = (rotr32(k[1], 8) + k[0]) ^ i
		k[0] = rotr32(k[0], 29) ^ k[3]
		k[1] = k[2]
		k[2] = t
	}
	return uint64(w0) | uint64(w1)<<32
}

func rotr32(v uint32, n uint) uint32 { return v>>n | v<<(32-n) }
