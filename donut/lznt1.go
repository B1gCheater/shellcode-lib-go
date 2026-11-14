package donut

// A portable LZNT1 compressor, so compressed shellcode can be generated on any
// host and comes out byte-identical everywhere. The port follows the public
// algorithm shared by the known open-source implementations; ntdll's own
// encoder makes different matcher choices, so streams are not byte-identical
// to RtlCompressBuffer's — they only have to be valid LZNT1, which is the
// format the loader stub hands to RtlDecompressBuffer. The tests validate
// every emitted stream through that exact API on Windows.
//
// Format recap: the input splits into 4096-byte chunks. Each chunk gets a
// 16-bit header, flag bits in the high nibble and size-1 in the low 12: a
// compressed chunk is 0xB000-flagged and holds tag groups (one flag byte per
// eight items, bit i set meaning item i is a 2-byte match token, clear
// meaning a literal); an incompressible chunk falls back to a raw copy under a
// 0x3000 header. Inside a chunk the offset/length split of the match token
// adapts to how far the chunk has expanded, which is what makes the encoder
// non-obvious: 12-bit lengths with 4-bit offsets at position zero, sliding by
// one bit each time the represented byte count crosses a power-of-two
// threshold.

const (
	lznt1Chunk = 4096 // the NT chunk size
	lznt1Min   = 3    // shortest match worth a token
	lznt1Max   = 4098 // hard limit: 12-bit length field plus three
	lznt1Depth = 16   // hash-chain entries inspected per position
	lznt1Mask  = 0xFFF
	lznt1Empty = 0xFFFF
	lznt1Comp  = 0xB000 // compressed chunk flag bits
	lznt1Raw   = 0x3000 // raw fallback flag bits
)

// compressLZNT1 compresses src into a stream RtlDecompressBuffer accepts. It
// never fails: a chunk that does not shrink is stored raw, exactly like every
// other LZNT1 encoder, so the output can only exceed the input by the two-byte
// chunk headers.
func compressLZNT1(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(src)/8+64)
	var head, chain [lznt1Chunk]uint16
	for pos := 0; pos < len(src); {
		size := len(src) - pos
		if size > lznt1Chunk {
			size = lznt1Chunk
		}
		chunk := src[pos : pos+size]

		start := len(out)
		out = append(out, 0, 0) // header slot, patched after
		out = lznt1ChunkCompress(chunk, out, &head, &chain)
		if csize := len(out) - start - 2; csize < size {
			h := lznt1Header(lznt1Comp, csize)
			out[start], out[start+1] = byte(h), byte(h>>8)
		} else {
			out = out[:start]
			h := lznt1Header(lznt1Raw, size)
			out = append(out, byte(h), byte(h>>8))
			out = append(out, chunk...)
		}
		pos += size
	}
	return out
}

// lznt1ChunkCompress emits one chunk's tag groups after the header slot
// already reserved at the end of out.
func lznt1ChunkCompress(chunk []byte, out []byte, head, chain *[lznt1Chunk]uint16) []byte {
	for i := range head {
		head[i] = lznt1Empty
	}

	// tagAccum groups up to eight items behind one flag byte, bit 0 first.
	var tag byte
	var tagItems int
	var group [16]byte
	var groupLen int
	flush := func() {
		if tagItems > 0 {
			out = append(out, tag)
			out = append(out, group[:groupLen]...)
			tag, tagItems, groupLen = 0, 0, 0
		}
	}
	pushLiteral := func(b byte) {
		group[groupLen] = b
		groupLen++
		tagItems++
		if tagItems == 8 {
			flush()
		}
	}
	pushTuple := func(t uint16) {
		tag |= 1 << tagItems
		group[groupLen] = byte(t)
		group[groupLen+1] = byte(t >> 8)
		groupLen += 2
		tagItems++
		if tagItems == 8 {
			flush()
		}
	}
	// remember links idx into the hash chain for a later match search.
	remember := func(idx int) {
		if idx+lznt1Min <= len(chunk) {
			h := lznt1Hash(chunk, idx)
			chain[idx] = head[h]
			head[h] = uint16(idx)
		}
	}

	// Adaptive offset/length split, donut- and NT-shared state machine: the
	// chunk begins with 12 bits of length and 4 of offset; each time the
	// represented byte count crosses threshold the split slides one bit toward
	// the offset side.
	split := 12
	threshold := 16
	represented := 0

	idx := 0
	for idx < len(chunk) {
		offBits := 16 - split
		maxOff := 1 << offBits

		bestLen, bestOff := 0, 0
		if idx+lznt1Min <= len(chunk) {
			cand := head[lznt1Hash(chunk, idx)]
			for depth := 0; cand != lznt1Empty && depth < lznt1Depth; depth++ {
				c := int(cand)
				if c >= idx {
					break
				}
				dist := idx - c
				if dist >= maxOff {
					break
				}
				// Fail fast on the byte just past the current best.
				if idx+bestLen < len(chunk) && chunk[c+bestLen] == chunk[idx+bestLen] {
					if n := lznt1Common(chunk[idx:], chunk[c:], lznt1Max); n >= lznt1Min && n > bestLen {
						bestLen, bestOff = n, dist
						if bestLen >= lznt1Max {
							bestLen = lznt1Max
							break
						}
					}
				}
				cand = chain[c]
			}
		}

		if bestLen >= lznt1Min {
			if cap := (1 << split) + 2; bestLen > cap {
				bestLen = cap
			}
			pushTuple(uint16(((bestOff - 1) << split) | (bestLen - 3)))
			for i := 0; i < bestLen; i++ {
				remember(idx)
				idx++
			}
			represented += bestLen
		} else {
			pushLiteral(chunk[idx])
			remember(idx)
			idx++
			represented++
		}

		for represented > threshold {
			if split > 0 {
				split--
			}
			threshold <<= 1
		}
	}
	flush()
	return out
}

// lznt1Header packs the flag bits and size-1 into a chunk header.
func lznt1Header(flag uint16, size int) uint16 {
	return flag | uint16((size-1)&lznt1Mask)
}

// lznt1Hash hashes the three bytes at off, matching the public implementations
// exactly: the shift arithmetic happens on wide integers, not bytes, or the
// high bits are lost before the mask.
func lznt1Hash(src []byte, off int) int {
	return (int(src[off])<<6 ^ int(src[off+1])<<3 ^ int(src[off+2])) & lznt1Mask
}

// lznt1Common counts the equal leading bytes of a and b, up to max. The
// comparison tolerates overlap, which is what lets a distance-1 match encode
// runs.
func lznt1Common(a, b []byte, max int) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	if max < limit {
		limit = max
	}
	n := 0
	for n < limit && a[n] == b[n] {
		n++
	}
	return n
}
