package donut

import (
	"encoding/binary"
	"fmt"
)

// Payload inspection.
//
// donut picks the module type from the file extension first and only then looks at
// the PE headers. This package has no file names, so it goes the other way: the
// headers decide, and they are unambiguous for the two kinds of module this
// library generates. IMAGE_FILE_DLL separates a DLL from an EXE, and a COM
// descriptor separates a managed image from a native one.
//
// Managed assemblies and scripts are rejected rather than downgraded. Silently
// treating a .NET assembly as a native image would produce shellcode whose first
// instruction is CLR metadata, and nothing would complain until it crashed on the
// target.

// PE constants used by the inspector.
const (
	dosSignature = 0x5A4D     // "MZ"
	ntSignature  = 0x00004550 // "PE\0\0"

	machineI386  = 0x014C
	machineAMD64 = 0x8664

	numDirEntries = 16

	fileDLL = 0x2000
)

// Info describes a payload after inspection.
type Info struct {
	// Type is ModuleDLL or ModuleEXE.
	Type int
	// Arch is ArchX86 or ArchX64, taken from the image's machine type.
	Arch int
	// Length is the payload size in bytes.
	Length uint32
}

type peHeaders struct {
	dos      []byte
	nt       []byte
	fileHdr  []byte
	optHdr   []byte
	sections []byte
	is32     bool
}

// parsePE validates the DOS and NT headers and locates the section table.
func parsePE(data []byte) (*peHeaders, error) {
	if len(data) < 64 {
		return nil, ErrFileInvalid
	}
	if binary.LittleEndian.Uint16(data) != dosSignature {
		return nil, ErrFileInvalid
	}
	ntOffset := binary.LittleEndian.Uint32(data[0x3C:])
	const ntFixedSize = 4 + 20
	if ntOffset < 64 || uint64(ntOffset) > uint64(len(data)-ntFixedSize) {
		return nil, ErrFileInvalid
	}
	lfanew := int(ntOffset)
	if binary.LittleEndian.Uint32(data[lfanew:]) != ntSignature {
		return nil, ErrFileInvalid
	}

	// IMAGE_NT_HEADERS: signature, FILE_HEADER (20 bytes), OPTIONAL_HEADER.
	fileHdrOff := lfanew + 4
	fileHdr := data[fileHdrOff : fileHdrOff+20]

	var optionalMagic uint16
	var directoryOffset int
	switch binary.LittleEndian.Uint16(fileHdr) {
	case machineI386:
		optionalMagic, directoryOffset = 0x10b, 96
	case machineAMD64:
		optionalMagic, directoryOffset = 0x20b, 112
	default:
		return nil, ErrFileInvalid
	}

	sizeOfOptional := int(binary.LittleEndian.Uint16(fileHdr[16:]))
	optHdrOff := fileHdrOff + 20
	if sizeOfOptional < directoryOffset+numDirEntries*8 || sizeOfOptional > len(data)-optHdrOff {
		return nil, ErrFileInvalid
	}
	optHdr := data[optHdrOff : optHdrOff+sizeOfOptional]
	if binary.LittleEndian.Uint16(optHdr) != optionalMagic {
		return nil, ErrFileInvalid
	}

	numSections := int(binary.LittleEndian.Uint16(fileHdr[2:]))
	sectionsOff := optHdrOff + sizeOfOptional
	if numSections == 0 || numSections > (len(data)-sectionsOff)/sectionHeaderSize {
		return nil, ErrFileInvalid
	}

	pe := &peHeaders{
		dos:      data[:lfanew],
		nt:       data[lfanew:],
		fileHdr:  fileHdr,
		optHdr:   optHdr,
		sections: data[sectionsOff : sectionsOff+numSections*sectionHeaderSize],
		is32:     optionalMagic == 0x10b,
	}
	for i := 0; i < numSections; i++ {
		_, rawSize, rawPtr := pe.section(i)
		if rawSize != 0 && uint64(rawPtr)+uint64(rawSize) > uint64(len(data)) {
			return nil, ErrFileInvalid
		}
	}
	return pe, nil
}

// dataDirectories returns the optional header's directory array.
func (p *peHeaders) dataDirectories() []byte {
	// 32-bit optional headers put the directories at offset 96, 64-bit at 112.
	off := 96
	if !p.is32 {
		off = 112
	}
	if off+numDirEntries*8 > len(p.optHdr) {
		return nil
	}
	return p.optHdr[off : off+numDirEntries*8]
}

func (p *peHeaders) directory(index int) (virtualAddress, size uint32) {
	dirs := p.dataDirectories()
	if dirs == nil || index >= numDirEntries {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(dirs[index*8:]), binary.LittleEndian.Uint32(dirs[index*8+4:])
}

func (p *peHeaders) numberOfSections() int { return len(p.sections) / sectionHeaderSize }

func (p *peHeaders) section(i int) (virtualAddress, sizeOfRawData, pointerToRawData uint32) {
	s := p.sections[i*sectionHeaderSize:]
	return binary.LittleEndian.Uint32(s[12:]), binary.LittleEndian.Uint32(s[16:]), binary.LittleEndian.Uint32(s[20:])
}

const sectionHeaderSize = 40

// rvaToOffset converts a relative virtual address to a file offset, or -1.
//
// This mirrors donut's rva2ofs, including its use of SizeOfRawData rather than
// VirtualSize when bounding the search.
func rvaToOffset(data []byte, p *peHeaders, rva uint32) int64 {
	for i := 0; i < p.numberOfSections(); i++ {
		va, rawSize, rawPtr := p.section(i)
		if rva >= va && rva-va < rawSize {
			off := int64(rawPtr) + int64(rva-va)
			if off < 0 || off >= int64(len(data)) {
				return -1
			}
			return off
		}
	}
	return -1
}

// Inspect reports the module type and architecture of a native PE payload held in
// memory. It is the question Build asks internally, exposed so a caller can filter
// a set of candidates, or find out why Build refused one, without building.
//
// A managed assembly returns ErrManagedImage. Anything that is not a valid PE
// image, scripts included, returns ErrFileInvalid; both come back with an empty
// Info.
func Inspect(data []byte) (Info, error) {
	return inspect(data, 0)
}

// inspect resolves the type, optionally against an asserted ModuleDLL or
// ModuleEXE from Config.ModuleType.
//
// The assertion is checked rather than trusted: a caller who labels a DLL as an
// EXE gets ErrInvalidType, because the loader would otherwise be told to run a
// DllMain-shaped entry as a process entry point. donut cannot do this check
// because it takes the extension as gospel; here there is no extension to lie.
func inspect(data []byte, asserted int) (Info, error) {
	if len(data) == 0 {
		return Info{}, ErrEmptyInput
	}
	pe, err := parsePE(data)
	if err != nil {
		return Info{}, err
	}

	comRVA, _ := pe.directory(dirEntryCOM)
	if comRVA != 0 {
		kind := "pure managed"
		if exportRVA, _ := pe.directory(dirEntryExport); exportRVA != 0 {
			// Mixed native and managed: unsupportable by the in-memory PE loader
			// even in donut, which rejects it outright.
			kind = "mixed native and managed"
		}
		return Info{}, fmt.Errorf("%w: this image is a .NET assembly (%s); this "+
			"package generates shellcode for native images only", ErrManagedImage, kind)
	}

	info := Info{Length: uint32(len(data)), Arch: ArchX64}
	if pe.is32 {
		info.Arch = ArchX86
	}
	isDLL := binary.LittleEndian.Uint16(pe.fileHdr[18:])&fileDLL != 0
	if isDLL {
		info.Type = ModuleDLL
	} else {
		info.Type = ModuleEXE
	}

	if asserted != 0 && asserted != info.Type {
		return Info{}, fmt.Errorf("%w: the image is a %s but ModuleType asserts a %s",
			ErrInvalidType, typeName(info.Type), typeName(asserted))
	}
	return info, nil
}

func typeName(t int) string {
	switch t {
	case ModuleDLL:
		return "DLL"
	case ModuleEXE:
		return "EXE"
	}
	return fmt.Sprintf("type %d", t)
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// hasExport reports whether a PE exports the named function. Name comparison is
// case sensitive, matching donut's own lookup, which is also case sensitive.
func hasExport(data []byte, pe *peHeaders, function string) bool {
	exportRVA, _ := pe.directory(dirEntryExport)
	if exportRVA == 0 {
		return false
	}
	off := rvaToOffset(data, pe, exportRVA)
	if off < 0 || off+40 > int64(len(data)) {
		return false
	}
	exp := data[off:]

	numberOfNames := binary.LittleEndian.Uint32(exp[24:])
	if numberOfNames == 0 {
		return false
	}
	addressOfNames := binary.LittleEndian.Uint32(exp[32:])

	namesOff := rvaToOffset(data, pe, addressOfNames)
	if namesOff < 0 || namesOff+int64(numberOfNames)*4 > int64(len(data)) {
		return false
	}
	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(data[namesOff+int64(i)*4:])
		nameOff := rvaToOffset(data, pe, nameRVA)
		if nameOff < 0 || nameOff >= int64(len(data)) {
			continue
		}
		end := indexByte(data[nameOff:], 0)
		if end < 0 {
			continue
		}
		if string(data[nameOff:int64(nameOff)+int64(end)]) == function {
			return true
		}
	}
	return false
}
