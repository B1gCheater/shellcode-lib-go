package test

import "encoding/binary"

// Synthetic PE builder for the regression tests. It emits a minimal but
// structurally valid native image (DOS + NT headers, one section) and lets a test
// drop a load-config or export directory into that section at a chosen RVA.
//
// Offsets follow the PE format and the SDK's IMAGE_LOAD_CONFIG_DIRECTORY32/64
// layouts; they are restated here so the tests are an independent check rather
// than a restatement of the code under test.

const (
	sectionRVA  = 0x1000
	sectionRaw  = 0x400
	sectionSize = 0x1000

	dirLoadConfig = 10
	dirExport     = 0
	dirTLS        = 9
)

type syntheticPE struct {
	data    []byte
	is32    bool
	isDLL   bool
	dataOff int // file offset of sectionRVA
	dirOff  int // file offset of the data-directory array
}

// newSyntheticPE builds an image with one readable/writable section. entry is the
// AddressOfEntryPoint (RVA); pass non-zero for a normal image.
func newSyntheticPE(is32, isDLL bool, entry uint32) *syntheticPE {
	const (
		lfanew     = 0x80
		fileHdrOff = lfanew + 4
		optOff     = fileHdrOff + 20
	)
	optSize := 224 // PE32: 96 standard/windows fields + 16*8 directories
	machine := uint16(0x014c)
	magic := uint16(0x10b)
	if !is32 {
		optSize = 240 // PE32+: 112 + 128
		machine = 0x8664
		magic = 0x20b
	}
	secOff := optOff + optSize
	headersSize := secOff + 40

	data := make([]byte, sectionRaw+sectionSize)
	p := &syntheticPE{data: data, is32: is32, isDLL: isDLL, dataOff: sectionRaw}

	binary.LittleEndian.PutUint16(data[0:], 0x5a4d) // MZ
	binary.LittleEndian.PutUint32(data[0x3c:], lfanew)
	binary.LittleEndian.PutUint32(data[lfanew:], 0x00004550) // PE\0\0

	// IMAGE_FILE_HEADER
	binary.LittleEndian.PutUint16(data[fileHdrOff:], machine)
	binary.LittleEndian.PutUint16(data[fileHdrOff+2:], 1) // NumberOfSections
	binary.LittleEndian.PutUint16(data[fileHdrOff+16:], uint16(optSize))
	chars := uint16(0x0002) // EXECUTABLE_IMAGE
	if isDLL {
		chars |= 0x2000 // IMAGE_FILE_DLL
	}
	if is32 {
		chars |= 0x0100 // 32BIT_MACHINE
	} else {
		chars |= 0x0020 // LARGE_ADDRESS_AWARE
	}
	binary.LittleEndian.PutUint16(data[fileHdrOff+18:], chars)

	// IMAGE_OPTIONAL_HEADER
	binary.LittleEndian.PutUint16(data[optOff:], magic)
	binary.LittleEndian.PutUint32(data[optOff+16:], entry) // AddressOfEntryPoint
	if is32 {
		binary.LittleEndian.PutUint32(data[optOff+28:], 0x00400000) // ImageBase
	} else {
		binary.LittleEndian.PutUint64(data[optOff+24:], 0x0000000140000000)
	}
	binary.LittleEndian.PutUint32(data[optOff+32:], 0x1000)              // SectionAlignment
	binary.LittleEndian.PutUint32(data[optOff+36:], 0x200)               // FileAlignment
	binary.LittleEndian.PutUint32(data[optOff+56:], 0x3000)              // SizeOfImage
	binary.LittleEndian.PutUint32(data[optOff+60:], uint32(headersSize)) // SizeOfHeaders
	binary.LittleEndian.PutUint16(data[optOff+68:], 3)                   // Subsystem: console

	numRvaOff := optOff + 92
	dirOff := optOff + 96
	if !is32 {
		numRvaOff = optOff + 108
		dirOff = optOff + 112
	}
	binary.LittleEndian.PutUint32(data[numRvaOff:], 16) // NumberOfRvaAndSizes
	p.dirOff = dirOff

	// Section header: ".data", RW, covering the whole data region.
	copy(data[secOff:secOff+8], []byte(".data\x00\x00\x00"))
	binary.LittleEndian.PutUint32(data[secOff+8:], sectionSize)  // VirtualSize
	binary.LittleEndian.PutUint32(data[secOff+12:], sectionRVA)  // VirtualAddress
	binary.LittleEndian.PutUint32(data[secOff+16:], sectionSize) // SizeOfRawData
	binary.LittleEndian.PutUint32(data[secOff+20:], sectionRaw)  // PointerToRawData
	binary.LittleEndian.PutUint32(data[secOff+36:], 0xC0000040)  // READ|WRITE|INITIALIZED_DATA

	return p
}

func (p *syntheticPE) setDir(index int, rva, size uint32) {
	binary.LittleEndian.PutUint32(p.data[p.dirOff+index*8:], rva)
	binary.LittleEndian.PutUint32(p.data[p.dirOff+index*8+4:], size)
}

// put writes b at the given RVA inside the section.
func (p *syntheticPE) put(rva uint32, b []byte) {
	off := p.dataOff + int(rva-sectionRVA)
	copy(p.data[off:], b)
}

func (p *syntheticPE) putU32(rva uint32, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	p.put(rva, b[:])
}

// addLoadConfig writes a load-config directory at sectionRVA. structSize is the
// value stored in the leading Size field; guardOffset/guardFlags place a GuardFlags
// dword (pass guardOffset<0 to omit). dirSize is the data-directory size entry.
// extraLen pads trailing bytes after the structure so a test can prove the reader
// does not run past the declared size into them.
func (p *syntheticPE) addLoadConfig(structSize, dirSize uint32, guardOffset int, guardFlags uint32, extraLen int) {
	total := int(structSize)
	if guardOffset >= 0 && guardOffset+4 > total {
		total = guardOffset + 4
	}
	total += extraLen
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:], structSize)
	if guardOffset >= 0 {
		binary.LittleEndian.PutUint32(buf[guardOffset:], guardFlags)
	}
	p.put(sectionRVA, buf)
	p.setDir(dirLoadConfig, sectionRVA, dirSize)
}

// addExports writes an export directory exporting the given names. Each name's
// function RVA points to a plausible code address past the directory, so none is
// a forwarder.
func (p *syntheticPE) addExports(names []string) {
	const expSize = 40
	n := len(names)
	ordOff := expSize + n*4
	namesOff := ordOff + n*2

	var nameBlob []byte
	nameRVAs := make([]uint32, n)
	for i, name := range names {
		nameRVAs[i] = sectionRVA + uint32(namesOff+len(nameBlob))
		nameBlob = append(nameBlob, []byte(name)...)
		nameBlob = append(nameBlob, 0)
	}
	funcOff := namesOff + len(nameBlob)
	total := funcOff + n*4

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[16:], 1)                        // Base
	binary.LittleEndian.PutUint32(buf[20:], uint32(n))                // NumberOfFunctions
	binary.LittleEndian.PutUint32(buf[24:], uint32(n))                // NumberOfNames
	binary.LittleEndian.PutUint32(buf[28:], sectionRVA+uint32(funcOff)) // AddressOfFunctions
	binary.LittleEndian.PutUint32(buf[32:], sectionRVA+expSize)       // AddressOfNames
	binary.LittleEndian.PutUint32(buf[36:], sectionRVA+uint32(ordOff)) // AddressOfNameOrdinals
	for i, rva := range nameRVAs {
		binary.LittleEndian.PutUint32(buf[expSize+i*4:], rva)
		binary.LittleEndian.PutUint16(buf[ordOff+i*2:], uint16(i))
	}
	copy(buf[namesOff:], nameBlob)
	funcBase := sectionRVA + uint32(total) + 0x100
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(buf[funcOff+i*4:], funcBase+uint32(i*16))
	}
	p.put(sectionRVA, buf)
	p.setDir(dirExport, sectionRVA, uint32(total))
}

// addTLS writes a TLS directory at sectionRVA. start/end are the raw-data template
// bounds (absolute VAs in a real image; the test only cares whether they differ),
// zeroFill is SizeOfZeroFill. The directory is placed after the export region if
// one exists, otherwise at sectionRVA+0x800 to avoid overlap.
func (p *syntheticPE) addTLS(start, end uint64, zeroFill uint32) {
	rva := uint32(sectionRVA + 0x800)
	zeroOff := 32
	dirLen := 40
	if p.is32 {
		zeroOff = 20
		dirLen = 24
	}
	buf := make([]byte, dirLen)
	if p.is32 {
		binary.LittleEndian.PutUint32(buf[0:], uint32(start))
		binary.LittleEndian.PutUint32(buf[4:], uint32(end))
	} else {
		binary.LittleEndian.PutUint64(buf[0:], start)
		binary.LittleEndian.PutUint64(buf[8:], end)
	}
	binary.LittleEndian.PutUint32(buf[zeroOff:], zeroFill)
	p.put(rva, buf)
	p.setDir(dirTLS, rva, uint32(dirLen))
}

// addForwardedExport writes an export directory where the named export forwards to
// target (a "DLL.Func" string stored inside the export directory).
func (p *syntheticPE) addForwardedExport(name, target string) {
	const expSize = 40
	// layout: [dir 40][names 4][ordinals 2][funcRVAs 4][name\0][target\0]
	ordOff := expSize + 4
	funcOff := ordOff + 2
	nameOff := funcOff + 4
	nameBytes := append([]byte(name), 0)
	targetOff := nameOff + len(nameBytes)
	targetBytes := append([]byte(target), 0)
	total := targetOff + len(targetBytes)

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[16:], 1)         // Base
	binary.LittleEndian.PutUint32(buf[20:], 1)         // NumberOfFunctions
	binary.LittleEndian.PutUint32(buf[24:], 1)         // NumberOfNames
	binary.LittleEndian.PutUint32(buf[28:], sectionRVA+uint32(funcOff)) // AddressOfFunctions
	binary.LittleEndian.PutUint32(buf[32:], sectionRVA+expSize)         // AddressOfNames
	binary.LittleEndian.PutUint32(buf[36:], sectionRVA+uint32(ordOff))  // AddressOfNameOrdinals
	binary.LittleEndian.PutUint32(buf[expSize:], sectionRVA+uint32(nameOff)) // name RVA
	binary.LittleEndian.PutUint16(buf[ordOff:], 0)     // ordinal 0
	// function RVA points at the target string INSIDE the directory => forwarder
	binary.LittleEndian.PutUint32(buf[funcOff:], sectionRVA+uint32(targetOff))
	copy(buf[nameOff:], nameBytes)
	copy(buf[targetOff:], targetBytes)
	p.put(sectionRVA, buf)
	p.setDir(dirExport, sectionRVA, uint32(total))
}