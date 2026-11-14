package donut

import (
	"encoding/binary"
)

// PE feature constants and small accessors used by the compatibility report.
//
// The offsets here were not hand-counted from documentation: they are printed by
// a program compiled against the same SDK headers the test payloads use
// (study/offsets.c in this project's working notes), so a silent mismatch with a
// future toolset shows up as a failed test rather than as a wrong report.
const (
	dirEntryExport      = 0  // IMAGE_DIRECTORY_ENTRY_EXPORT
	dirEntryImport      = 1  // IMAGE_DIRECTORY_ENTRY_IMPORT
	dirEntryException   = 3  // IMAGE_DIRECTORY_ENTRY_EXCEPTION (x64 .pdata)
	dirEntryBaseReloc   = 5  // IMAGE_DIRECTORY_ENTRY_BASERELOC
	dirEntryTLS         = 9  // IMAGE_DIRECTORY_ENTRY_TLS
	dirEntryLoadConfig  = 10 // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
	dirEntryBoundImport = 11 // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
	dirEntryIAT         = 12 // IMAGE_DIRECTORY_ENTRY_IAT
	dirEntryDelayImport = 13 // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
	dirEntryCOM         = 14 // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
)

const (
	// IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags.
	loadCfg64GuardFlags = 144
	// IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT.
	imageGuardCFTablePresent = 0x00000400

	// IMAGE_DLLCHARACTERISTICS_GUARD_CF.
	imageDllCharacteristicsGuardCF = 0x4000

	// IMAGE_SCN_MEM_WRITE / IMAGE_SCN_MEM_EXECUTE.
	imageScnMemWrite   = 0x80000000
	imageScnMemExecute = 0x20000000

	// IMAGE_TLS_DIRECTORY64 field offsets, for the report and for any future
	// TLS index allocation: the loader currently reads only AddressOfCallBacks.
	tls64StartAddressOfRawData = 0
	tls64EndAddressOfRawData   = 8
	tls64AddressOfIndex        = 16
	tls64AddressOfCallBacks    = 24
	tls64SizeOfZeroFill        = 32
)

// directory returns the (rva, size) pair for one data directory entry.
func directory(dirs []byte, index int) (rva, size uint32) {
	if dirs == nil || index < 0 || index >= numDirEntries {
		return 0, 0
	}
	return binary.LittleEndian.Uint32(dirs[index*8:]), binary.LittleEndian.Uint32(dirs[index*8+4:])
}

// imageBaseOf returns the optional header's preferred image base.
func imageBaseOf(pe *peHeaders) uint64 {
	if pe.is32 {
		return uint64(binary.LittleEndian.Uint32(pe.optHdr[28:]))
	}
	return binary.LittleEndian.Uint64(pe.optHdr[24:])
}

// dllCharacteristics returns the optional header's DllCharacteristics field,
// which sits at the same offset in both the 32- and 64-bit layouts.
func (p *peHeaders) dllCharacteristics() uint16 {
	return binary.LittleEndian.Uint16(p.optHdr[70:])
}

// sectionCharacteristics returns one section's flags word.
func sectionCharacteristics(pe *peHeaders, i int) uint32 {
	s := pe.sections[i*sectionHeaderSize:]
	return binary.LittleEndian.Uint32(s[36:])
}
