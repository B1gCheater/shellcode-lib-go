package donut

import (
	"encoding/binary"
	"errors"
)

// Shellcode assembly, a port of donut's build_loader().
//
// The layout is
//
//	E8 <inst_len>          call $+5, which pushes the address of the instance
//	<instance>             DONUT_INSTANCE followed by the module blob
//	59                     pop ecx   ; ecx = instance
//	<arch specific tail>   the loader stub for the target architecture
//
// The instance begins at offset 5: the prologue is the five-byte call, and the
// "pop ecx" that consumes the pushed address comes *after* the instance, as the
// first byte of the arch tail.
//
// The x86 tail is
//
//	5A 51 52               pop edx ; push ecx ; push edx
//	<x86 loader>
//
// and the amd64 tail is
//
//	<22 byte RSP align prologue>
//	<x64 loader>
//
// The dual-mode tail carries both, selected at run time.

// x64RSPAlign is donut's LOADER_EXE_X64_RSP_ALIGN prologue, 22 bytes long. It
// sets up a frame and aligns RSP to 16 bytes before entering the amd64 loader,
// which matters because the Microsoft x64 calling convention requires it.
var x64RSPAlign = []byte{
	0x55,             // push rbp
	0x48, 0x89, 0xE5, // mov rbp, rsp
	0x48, 0x83, 0xE4, 0xF0, // and rsp, -0x10
	0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
	0xE8, 0x05, 0x00, 0x00, 0x00, // call $+5
	0x48, 0x89, 0xEC, // mov rsp, rbp
	0x5D, // pop rbp
	0xC3, // ret
}

// picPrologueLen is the size of the "call rel32" that precedes the instance, so
// the instance begins at this offset in the shellcode.
const picPrologueLen = 5

// dualModeStub is the run time architecture selector. It relies on the fact that
// 0x48 is DEC EAX on x86 (setting SF) but the REX prefix of a 64-bit instruction
// on amd64, so a single byte dispatches either way. The five bytes are
// xor eax,eax / dec eax / js rel32, and the four-byte displacement that follows
// is part of the instruction; buildPic explains where it points.
var dualModeStub = []byte{0x31, 0xC0, 0x48, 0x0F, 0x88}

// buildPic assembles the complete shellcode. The loader tail is the enhanced
// stub pair (zz_loader_blobs_enhanced.go, README.md); there is no
// second loader to select.
func buildPic(arch int, inst *instance) ([]byte, error) {
	blob, err := inst.marshal()
	if err != nil {
		return nil, err
	}

	switch arch {
	case ArchX86, ArchX64, ArchX84:
	default:
		return nil, errors.New("donut: invalid architecture")
	}

	// The prologue plus instance plus pop ecx, then the architecture tail.
	pic := make([]byte, 0, picPrologueLen+len(blob)+len(loaderEnhancedX86)+len(loaderEnhancedX64)+64)

	pic = append(pic, 0xE8)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(blob)))
	pic = append(pic, lenBuf[:]...)
	pic = append(pic, blob...)
	pic = append(pic, 0x59) // pop ecx

	switch arch {
	case ArchX86:
		pic = append(pic, 0x5A, 0x51, 0x52) // pop edx ; push ecx ; push edx
		pic = append(pic, loaderEnhancedX86...)

	case ArchX64:
		pic = append(pic, x64RSPAlign...)
		pic = append(pic, loaderEnhancedX64...)

	case ArchX84:
		pic = append(pic, dualModeStub...)
		// js rel32 into the x86 path.
		//
		// donut writes sizeof(x64RSPAlign) + sizeof(its x64 loader) as a 32-bit
		// displacement. A rel32 is measured from the byte after the instruction,
		// which is where the RSP prologue begins, so the branch lands three bytes
		// before the x86 loader - precisely on the pop edx / push ecx / push edx
		// preamble that the x86 path needs anyway. Verified against generated
		// shellcode: the byte at the branch target is 0x5A and the x86 loader
		// follows it intact. The same formula is used here with the enhanced
		// x64 stub, and the dual-arch path is executed on both host bitnesses by
		// the end-to-end suite.
		//
		// donut's PUT_WORD macro writes four bytes despite the name; this uses a
		// 32-bit write to match, which also keeps the output correct if a future
		// loader blob exceeds 64 KiB.
		var disp [4]byte
		binary.LittleEndian.PutUint32(disp[:], uint32(len(x64RSPAlign)+len(loaderEnhancedX64)))
		pic = append(pic, disp[:]...)

		pic = append(pic, x64RSPAlign...)
		pic = append(pic, loaderEnhancedX64...)
		pic = append(pic, 0x5A, 0x51, 0x52)
		pic = append(pic, loaderEnhancedX86...)
	}

	// build_loader mallocs loader + inst_len + 32 bytes and writes fewer than
	// that, so the tail of the buffer is the zeroed slack. The size depends only
	// on the blob sizes, never on the payload:
	//
	//	x86            32 - 9  = 23 bytes
	//	amd64          32 - 6  = 26 bytes
	//	x86 + amd64    32 - 18 = 14 bytes
	//
	// where 9, 6 and 18 are the bytes the prologue and arch preamble consume
	// against the constant. Measured from donut builds across payloads from
	// 4.6 KB to 2.4 MB. Reproduced because the goal is byte identical output; the
	// bytes are never executed.
	for i := 0; i < tailPad(arch); i++ {
		pic = append(pic, 0)
	}

	return pic, nil
}

// tailPad returns the trailing zero padding donut's realloc leaves behind.
func tailPad(arch int) int {
	switch arch {
	case ArchX86:
		return 23
	case ArchX84:
		return 14
	default:
		return 26
	}
}
