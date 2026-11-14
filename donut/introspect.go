package donut

import "encoding/binary"

// Introspection helpers.
//
// These exist so that tooling and tests can inspect generated shellcode: peel
// off the instance encryption the way the loader does, and read the fields back.
// They are not needed to generate shellcode.

// InstanceKeyOffset is the offset of the 32-byte key material inside
// DONUT_INSTANCE: a 16-byte master key followed by a 16-byte counter.
const InstanceKeyOffset = instOffKey

// InstanceIVOffset is the offset of the 64-bit MARU initial value.
const InstanceIVOffset = instOffIV

// PrologueLen is the size of the "call $+5 / pop ecx" prologue that precedes the
// instance in generated shellcode.
const PrologueLen = picPrologueLen

// ModuleHeaderSize is the size of DONUT_MODULE's fixed header, before the
// payload. DONUT_MODULE.data is a flexible array member in C.
const ModuleHeaderSize = moduleSize

// ModuleDataOffset is the offset of the payload inside DONUT_MODULE.
const ModuleDataOffset = modOffData

// ModuleStartOffset is the offset of the module blob inside DONUT_INSTANCE.
// The payload therefore begins at ModuleStartOffset + ModuleDataOffset.
const ModuleStartOffset = instOffModule

// Field offsets inside DONUT_MODULE. Add one of these to ModuleStartOffset (and
// then to PrologueLen) to locate the field in generated shellcode; ModuleString
// does that arithmetic for you.
const (
	ModuleTypeOffset      = modOffType
	ModuleCompOffset      = modOffComp
	ModuleRuntimeOffset   = modOffRuntime
	ModuleDomainOffset    = modOffDomain
	ModuleClassOffset     = modOffClass
	ModuleMethodOffset    = modOffMethod
	ModuleArgsOffset      = modOffArgs
	ModuleUnicodeOffset   = modOffUnicode
	ModuleZLenOffset      = modOffZLen
	ModuleLenOffset       = modOffLen
	InstanceDecoyOffset   = instOffDecoy
	InstanceBypassOffset  = instOffBypass
	InstanceHeadersOffset = instOffHeaders
)

// fieldWidths is the byte width of each exported string field. donut copies
// these with strncpy into a zeroed buffer, so a value that exactly fills its
// field has no terminator; the reader must stop at the field boundary rather
// than scan forward.
var fieldWidths = map[int]int{
	ModuleRuntimeOffset: maxName,
	ModuleDomainOffset:  maxName,
	ModuleClassOffset:   maxName,
	ModuleMethodOffset:  maxName,
	ModuleArgsOffset:    maxName,
	InstanceDecoyOffset: decoyLen,
}

func readField(pic []byte, start, offset int) string {
	width, ok := fieldWidths[offset]
	if !ok {
		width = maxName
	}
	end := start + width
	if end > len(pic) {
		end = len(pic)
	}
	return cstring(pic[start:end])
}

// ModuleString reads a NUL-terminated field of DONUT_MODULE out of generated
// shellcode. fieldOffset is one of the Module*Offset constants.
//
// A field that the module type cannot use is empty, which is how a caller (or a
// test) confirms the field scoping donut applies: a .NET EXE carries no class or
// method, and an unmanaged EXE carries no runtime, domain or method.
//
// The result is meaningful without decryption only when Config.Entropy was
// EntropyNone; for encrypted output, run DecryptInstance first.
func ModuleString(pic []byte, fieldOffset int) (string, bool) {
	start := PrologueLen + ModuleStartOffset + fieldOffset
	if start < 0 || start >= len(pic) {
		return "", false
	}
	return readField(pic, start, fieldOffset), true
}

// InstanceString reads a NUL-terminated field of DONUT_INSTANCE out of generated
// shellcode. fieldOffset is one of the Instance*Offset constants.
func InstanceString(pic []byte, fieldOffset int) (string, bool) {
	start := PrologueLen + fieldOffset
	if start < 0 || start >= len(pic) {
		return "", false
	}
	return readField(pic, start, fieldOffset), true
}

// InstanceInt reads a 32-bit integer field of DONUT_INSTANCE, for offsets like
// InstanceBypassOffset and InstanceHeadersOffset whose contents are ints rather
// than strings.
func InstanceInt(pic []byte, fieldOffset int) (int, bool) {
	start := PrologueLen + fieldOffset
	if fieldOffset < 0 || start < 0 || start > len(pic)-4 {
		return 0, false
	}
	return int(int32(binary.LittleEndian.Uint32(pic[start:]))), true
}

// ModuleInt reads a 32-bit integer field of DONUT_MODULE, for offsets like
// ModuleTypeOffset and ModuleUnicodeOffset.
func ModuleInt(pic []byte, fieldOffset int) (int, bool) {
	start := PrologueLen + ModuleStartOffset + fieldOffset
	if fieldOffset < 0 || start < 0 || start > len(pic)-4 {
		return 0, false
	}
	return int(int32(binary.LittleEndian.Uint32(pic[start:]))), true
}

// cstring returns s up to the first NUL.
func cstring(s []byte) string {
	if n := indexByte(s, 0); n >= 0 {
		return string(s[:n])
	}
	return string(s)
}

// Fields is a decoded view of the instance inside a shellcode blob.
type Fields struct {
	Len       uint32
	IV        uint64
	APICnt    uint32
	ExitOpt   int
	Entropy   int
	OEP       uint32
	Sig       string
	Mac       uint64
	ModKey    [cryptSize]byte
	ModuleLen uint64
}

// InstanceFields reads the fixed instance fields. The offsets before api_cnt are
// never encrypted, so most values are readable without decrypting; Sig and the
// remaining fields inside DONUT_MODULE require DecryptInstance first.
func InstanceFields(pic []byte) (Fields, bool) {
	const instOff = PrologueLen
	if len(pic) < instOff+InstanceSize {
		return Fields{}, false
	}
	inst := pic[instOff:]

	var f Fields
	f.Len = binary.LittleEndian.Uint32(inst[instOffLen:])
	f.IV = binary.LittleEndian.Uint64(inst[instOffIV:])
	f.APICnt = binary.LittleEndian.Uint32(inst[instOffAPICnt:])
	f.ExitOpt = int(binary.LittleEndian.Uint32(inst[instOffExitOpt:]))
	f.Entropy = int(binary.LittleEndian.Uint32(inst[instOffEntropy:]))
	f.OEP = binary.LittleEndian.Uint32(inst[instOffOEP:])
	f.Mac = binary.LittleEndian.Uint64(inst[instOffMac:])
	copy(f.ModKey[:], inst[instOffModKey:instOffModKey+cryptSize])
	f.ModuleLen = binary.LittleEndian.Uint64(inst[instOffModLen:])

	// The signature is a NUL-terminated string inside the encrypted region.
	sig := inst[instOffSig : instOffSig+maxName]
	if n := indexByte(sig, 0); n >= 0 {
		sig = sig[:n]
	}
	f.Sig = string(sig)
	return f, true
}

// DecryptInstance peels off the instance encryption in place on a copy, which is
// what the loader does before it verifies the MAC and runs the module.
//
// Only the instance layer exists for an embedded module: the module's own key is
// used solely by the HTTP staging path, which this package does not generate.
//
// The counter half of the key material is advanced as a side effect, exactly as
// in donut's loader, so the key bytes read back from a decrypted copy are no
// longer the original ones.
func DecryptInstance(pic []byte) []byte {
	const instOff = PrologueLen
	if len(pic) < instOff+InstanceSize {
		return pic
	}

	out := make([]byte, len(pic))
	copy(out, pic)
	inst := out[instOff:]

	instLen := binary.LittleEndian.Uint32(inst[instOffLen:])
	if instLen < InstanceSize || uint64(instLen) > uint64(len(inst)) {
		return out
	}

	var key [cryptSize]byte
	copy(key[:], inst[instOffKey:instOffKey+cryptSize])

	donutEncrypt(key[:16], key[16:32], inst[instOffAPICnt:instLen])
	return out
}
