package donut

import (
	"bytes"
	"math/rand"
	"testing"
)

// depackAPLib is a Go port of depack.c's aP_depack, used only to round-trip the
// compressor's output. It exists so the compressor can be validated on every
// host without the Windows loader; the Windows e2e test additionally validates
// against the loader's real C aP_depack.

type apdState struct {
	src      []byte
	pos      int
	tag      byte
	bitcount int
}

func (s *apdState) getbit() uint {
	if s.bitcount == 0 {
		s.tag = s.src[s.pos]
		s.pos++
		s.bitcount = 7
	} else {
		s.bitcount--
	}
	bit := (s.tag >> 7) & 1
	s.tag <<= 1
	return uint(bit)
}

func (s *apdState) getgamma() uint32 {
	result := uint32(1)
	for {
		result = (result << 1) + uint32(s.getbit())
		if s.getbit() == 0 {
			break
		}
	}
	return result
}

func depackAPLib(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	s := &apdState{src: src}
	out := make([]byte, 0, len(src)*2)

	out = append(out, s.src[s.pos])
	s.pos++

	R0 := uint32(0xFFFFFFFF) // (unsigned int)-1 in depack.c
	LWM := uint32(0)
	done := false

	for !done {
		if s.getbit() == 1 {
			if s.getbit() == 1 {
				if s.getbit() == 1 {
					offs := uint32(0)
					for i := 0; i < 4; i++ {
						offs = (offs << 1) + uint32(s.getbit())
					}
					if offs != 0 {
						out = append(out, out[len(out)-int(offs)])
					} else {
						out = append(out, 0)
					}
					LWM = 0
				} else {
					b := s.src[s.pos]
					s.pos++
					offs := uint32(b >> 1)
					ln := 2 + int(b&1)
					if offs != 0 {
						for ; ln > 0; ln-- {
							out = append(out, out[len(out)-int(offs)])
						}
					} else {
						done = true
					}
					R0 = offs
					LWM = 1
				}
			} else {
				offs := s.getgamma()
				if LWM == 0 && offs == 2 {
					offs = R0
					ln := s.getgamma()
					for ; ln > 0; ln-- {
						out = append(out, out[len(out)-int(offs)])
					}
				} else {
					if LWM == 0 {
						offs -= 3
					} else {
						offs -= 2
					}
					offs <<= 8
					offs += uint32(s.src[s.pos])
					s.pos++
					ln := s.getgamma()
					if offs >= 32000 {
						ln++
					}
					if offs >= 1280 {
						ln++
					}
					if offs < 128 {
						ln += 2
					}
					for ; ln > 0; ln-- {
						out = append(out, out[len(out)-int(offs)])
					}
					R0 = offs
				}
				LWM = 1
			}
		} else {
			out = append(out, s.src[s.pos])
			s.pos++
			LWM = 0
		}
	}
	return out
}

func TestAPLibRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00},
		{0x41},
		{0x41, 0x41, 0x41, 0x41},
		[]byte("hello world"),
		bytes.Repeat([]byte{0x00}, 1000),
		bytes.Repeat([]byte{0x41}, 4096),
		bytes.Repeat([]byte("abcdefgh"), 512),
		[]byte("the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog."),
	}
	// A small deterministic image-like blob with runs and repeats.
	img := make([]byte, 2048)
	for i := range img {
		img[i] = byte(i % 251)
	}
	img[500] = img[499]
	img[600] = img[599]
	cases = append(cases, img)

	for ci, in := range cases {
		comp := compressAPLib(in)
		got := depackAPLib(comp)
		if !bytes.Equal(got, in) {
			t.Fatalf("case %d (len=%d): round-trip mismatch\n in =%x\n got=%x\ncomp=%x",
				ci, len(in), in, got, comp)
		}
	}
}

func TestAPLibRandomRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	sizes := []int{0, 1, 2, 3, 7, 16, 127, 128, 255, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		for rep := 0; rep < 20; rep++ {
			in := make([]byte, size)
			switch rep % 4 {
			case 0: // uniform random
				rng.Read(in)
			case 1: // skewed toward repeated bytes
				for i := range in {
					in[i] = byte(rng.Intn(8))
				}
			case 2: // runs of identical bytes
				run := byte(rng.Intn(256))
				for i := range in {
					if rng.Intn(3) == 0 {
						run = byte(rng.Intn(256))
					}
					in[i] = run
				}
			case 3: // zeros with scattered bytes
				for i := range in {
					if rng.Intn(16) == 0 {
						in[i] = byte(rng.Intn(256))
					}
				}
			}
			comp := compressAPLib(in)
			got := depackAPLib(comp)
			if !bytes.Equal(got, in) {
				t.Fatalf("size=%d rep=%d: round-trip mismatch (comp=%d bytes)", size, rep, len(comp))
			}
		}
	}
}

func TestAPLibCompressesRepetitive(t *testing.T) {
	in := bytes.Repeat([]byte{0xAB}, 8192)
	comp := compressAPLib(in)
	if len(comp) >= len(in) {
		t.Fatalf("repetitive input should compress: got %d bytes for %d input", len(comp), len(in))
	}
}

func TestAPLibFirstByteVerbatim(t *testing.T) {
	in := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	comp := compressAPLib(in)
	if len(comp) == 0 || comp[0] != in[0] {
		t.Fatalf("first byte must be verbatim: comp[0]=%#x want %#x", comp[0], in[0])
	}
}
