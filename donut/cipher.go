package donut

import "encoding/binary"

// Chaskey, donut's block cipher, used in counter mode as a stream cipher. The
// key material is a DONUT_CRYPT value: a 16-byte master key followed by a
// 16-byte counter and nonce. donutEncrypt encrypts and decrypts, because CTR
// mode is its own inverse.
//
// The counter is advanced in place, exactly as donut does. That matters to
// callers: after encrypting or decrypting, the counter half of the key material
// has moved forward, which is why Build must encrypt a whole region in one call
// and why nothing may re-enter with the same buffer.

const cipherBlockLen = 16

// chaskey is donut's ENCRYPT macro: 16 rounds over four 32-bit words with the
// key mixed in at both ends.
func chaskey(mk []byte, p []byte) {
	var w, k [4]uint32
	for i := 0; i < 4; i++ {
		w[i] = binary.LittleEndian.Uint32(p[i*4:])
		k[i] = binary.LittleEndian.Uint32(mk[i*4:])
	}

	for i := 0; i < 4; i++ {
		w[i] ^= k[i]
	}
	for i := 0; i < 16; i++ {
		w[0] += w[1]
		w[1] = rotr32(w[1], 27) ^ w[0]
		w[2] += w[3]
		w[3] = rotr32(w[3], 24) ^ w[2]
		w[2] += w[1]
		w[0] = rotr32(w[0], 16) + w[3]
		w[3] = rotr32(w[3], 19) ^ w[0]
		w[1] = rotr32(w[1], 25) ^ w[2]
		w[2] = rotr32(w[2], 16)
	}
	for i := 0; i < 4; i++ {
		w[i] ^= k[i]
	}

	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(p[i*4:], w[i])
	}
}

// donutEncrypt applies the Chaskey-CTR stream to data in place and advances ctr.
func donutEncrypt(mk, ctr, data []byte) {
	var x [cipherBlockLen]byte

	for len(data) > 0 {
		copy(x[:], ctr)
		chaskey(mk, x[:])

		n := cipherBlockLen
		if len(data) < n {
			n = len(data)
		}
		for i := 0; i < n; i++ {
			data[i] ^= x[i]
		}
		data = data[n:]

		// Increment the 128-bit counter, least significant byte last.
		for i := cipherBlockLen; i > 0; i-- {
			ctr[i-1]++
			if ctr[i-1] != 0 {
				break
			}
		}
	}
}
