package donut

// A portable aPLib compressor, so CompressAPLib can generate on any host.
//
// The output is a valid aPLib stream decodable by the loader stub's aP_depack
// (depack.c). It is not byte-identical to the reference C aP_pack: like the
// LZNT1 encoder, it makes its own match choices and only has to produce the
// format aP_depack consumes. The tests round-trip every emitted stream through a
// Go port of aP_depack on every host, and through the loader's C aP_depack on
// Windows.
//
// Format, derived from depack.c (not from the packer): the first byte is copied
// verbatim; the stream is then a sequence of tokens, each introduced by control
// bits read MSB-first from tag bytes:
//
//	0         literal: the next byte is copied as-is (LWM=0)
//	1 1 1     short match: a 4-bit offset 1-15 copies one byte (LWM=0); the
//	          offset 0 writes a single zero byte
//	1 1 0     single match: a raw byte b encodes offset=b>>1, length=2+(b&1);
//	          offset 0 is the end-of-stream marker (R0=off, LWM=1)
//	1 0       gamma match: a gamma offset, then (except on R0 reuse) a raw low
//	          offset byte, then a gamma length (R0=off, LWM=1)
//
// The gamma code is aPLib's variant: a value V>=2 is its binary body (the bits
// below the leading 1) emitted MSB-first, each bit followed by a "more bits"
// continuation flag. Tag bytes are written to the stream at the position the
// decoder first needs them, which is why the encoder reserves the tag slot up
// front rather than flushing a completed byte after the data it tags.

const (
	aplibWindow = 65535 // match search window
	aplibDepth  = 64    // hash-chain entries inspected per position
)

// compressAPLib compresses src into an aPLib stream. It never fails: aPLib has
// no stored-raw fallback, so incompressible input encodes as literals and the
// output can exceed the input. The loader decompresses into mod->len bytes and
// stops at the end-of-stream marker, so a larger-than-input stream is fine.
func compressAPLib(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	e := &aplibEncoder{src: src, tagIndex: -1}
	return e.run()
}

type aplibEncoder struct {
	src      []byte
	out      []byte
	tagIndex int // index of the in-progress tag byte in out, -1 if none
	bitCount int // bits filled in the current tag (0..8)
	r0       int // last non-reuse offset (R0)
	lwm      bool
}

// putBit appends one control bit. The tag byte's slot in out is reserved the
// first time a bit is added to it, so the tag precedes the data bytes that
// follow its first bit — the exact interleaving aP_depack expects.
func (e *aplibEncoder) putBit(b uint) {
	if e.tagIndex < 0 {
		e.out = append(e.out, 0)
		e.tagIndex = len(e.out) - 1
		e.bitCount = 0
	}
	if b != 0 {
		e.out[e.tagIndex] |= 1 << (7 - e.bitCount)
	}
	e.bitCount++
	if e.bitCount == 8 {
		e.tagIndex = -1
	}
}

// putGamma emits a gamma value. v must be >= 2: the aPLib gamma has an implicit
// leading 1, so the smallest representable value is 2.
func (e *aplibEncoder) putGamma(v uint32) {
	top := uint(0)
	for (v >> top) > 1 {
		top++
	}
	for i := int(top) - 1; i >= 0; i-- {
		e.putBit(uint((v >> uint(i)) & 1))
		if i > 0 {
			e.putBit(1)
		} else {
			e.putBit(0)
		}
	}
}

// gammaAdjust is the length correction the decoder applies based on the match
// offset, mirrored from depack.c.
func (e *aplibEncoder) gammaAdjust(off int) int {
	adj := 0
	if off >= 32000 {
		adj++
	}
	if off >= 1280 {
		adj++
	}
	if off < 128 {
		adj += 2
	}
	return adj
}

func (e *aplibEncoder) emitLiteral(b byte) {
	e.putBit(0)
	e.out = append(e.out, b)
	e.lwm = false
}

func (e *aplibEncoder) emitShortMatch(off int) {
	// off == 0 writes a zero byte; 1-15 copies one byte.
	e.putBit(1)
	e.putBit(1)
	e.putBit(1)
	for i := 3; i >= 0; i-- {
		e.putBit(uint((off >> i) & 1))
	}
	e.lwm = false
}

func (e *aplibEncoder) emitSingleMatch(off, ln int) {
	// off in 1..127, ln in 2..3.
	e.putBit(1)
	e.putBit(1)
	e.putBit(0)
	e.out = append(e.out, byte((off<<1)|(ln-2)))
	e.r0 = off
	e.lwm = true
}

func (e *aplibEncoder) emitR0Reuse(ln int) {
	// The "offset gamma == 2 while LWM == 0" form reuses R0; length is a bare
	// gamma. ln must be >= 2.
	e.putBit(1)
	e.putBit(0)
	e.putGamma(2)
	e.putGamma(uint32(ln))
	e.lwm = true // R0 is unchanged
}

func (e *aplibEncoder) emitGammaMatch(off, ln int) {
	e.putBit(1)
	e.putBit(0)
	gOff := off >> 8
	if e.lwm {
		gOff += 2
	} else {
		gOff += 3
	}
	e.putGamma(uint32(gOff))
	e.out = append(e.out, byte(off&0xFF))
	e.putGamma(uint32(ln - e.gammaAdjust(off)))
	e.r0 = off
	e.lwm = true
}

// end emits the end-of-stream marker: a single match whose raw byte is 0.
func (e *aplibEncoder) end() {
	e.putBit(1)
	e.putBit(1)
	e.putBit(0)
	e.out = append(e.out, 0x00)
}

func (e *aplibEncoder) run() []byte {
	src := e.src

	// First byte is verbatim, before any tag.
	e.out = append(e.out, src[0])

	const n = 65536
	head := make([]int32, n)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int32, len(src))
	for i := range prev {
		prev[i] = -1
	}
	hash2 := func(i int) int {
		return (int(src[i]) << 8) | int(src[i+1])
	}

	i := 1
	for i < len(src) {
		bestLen, bestOff := 0, 0
		if i+1 < len(src) {
			h := hash2(i)
			depth := aplibDepth
			for cand := head[h]; cand >= 0 && depth > 0; cand = prev[cand] {
				depth--
				off := i - int(cand)
				if off > aplibWindow {
					break
				}
				if src[cand] != src[i] || src[cand+1] != src[i+1] {
					continue
				}
				ln := 2
				for i+ln < len(src) && int(cand)+ln < len(src) && src[i+ln] == src[int(cand)+ln] {
					ln++
				}
				if ln > bestLen || (ln == bestLen && off < bestOff) {
					bestLen, bestOff = ln, off
					if bestLen == len(src)-i {
						break
					}
				}
			}
		}

		if bestLen >= 2 {
			encoded := false
			switch {
			case !e.lwm && bestOff == e.r0:
				// Reusing R0 is always cheaper than a fresh offset.
				e.emitR0Reuse(bestLen)
				encoded = true
			case bestLen <= 3 && bestOff <= 127:
				e.emitSingleMatch(bestOff, bestLen)
				encoded = true
			case bestLen >= 2+e.gammaAdjust(bestOff):
				e.emitGammaMatch(bestOff, bestLen)
				encoded = true
			}
			if encoded {
				for k := 0; k < bestLen; k++ {
					if i+1 < len(src) {
						h := hash2(i)
						prev[i] = head[h]
						head[h] = int32(i)
					}
					i++
				}
				continue
			}
			// A match that no token can express at this offset: fall through
			// and emit a literal so progress is guaranteed.
		}

		switch {
		case src[i] == 0:
			e.emitShortMatch(0)
		default:
			off := 0
			for d := 1; d <= 15 && i-d >= 0; d++ {
				if src[i-d] == src[i] {
					off = d
					break
				}
			}
			if off != 0 {
				e.emitShortMatch(off)
			} else {
				e.emitLiteral(src[i])
			}
		}
		if i+1 < len(src) {
			h := hash2(i)
			prev[i] = head[h]
			head[h] = int32(i)
		}
		i++
	}

	e.end()
	return e.out
}
