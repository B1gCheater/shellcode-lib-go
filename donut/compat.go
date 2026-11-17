package donut

import (
	"encoding/binary"
	"fmt"
)

// Payload compatibility reporting.
//
// The loader maps images by hand instead of asking the OS, which it can only get
// away with for payloads whose startup does not depend on loader services it did
// not reproduce. Some of those gaps were measured rather than assumed - see
// README.md for the experiments and the numbers - and Compat turns
// them into a machine-readable report so a caller can decide whether a payload is
// worth generating at all.
//
// Two principles shaped this API:
//
//   - Report only what has evidence behind it. There is deliberately no
//     "static CRT detector": the measured static-CRT failures cannot be told
//     apart from working hand-written payloads by header features alone, so
//     guessing would be worse than staying quiet.
//   - Separate knowing from blocking. Compat refuses nothing; Build only refuses
//     when Config.Strict is set and an issue is a blocker.

// CompatLevel says how much an issue matters.
type CompatLevel uint8

const (
	// CompatInfo is worth knowing but does not change the outcome.
	CompatInfo CompatLevel = iota + 1
	// CompatWarning marks behaviour that was measured to be degraded or wrong.
	CompatWarning
	// CompatBlock marks a payload this loader cannot run correctly at all.
	CompatBlock
)

func (l CompatLevel) String() string {
	switch l {
	case CompatInfo:
		return "info"
	case CompatWarning:
		return "warning"
	case CompatBlock:
		return "block"
	}
	return "unknown"
}

// CompatCode identifies an issue. Codes are stable strings so callers can switch
// on them and so reports stay readable in logs.
type CompatCode string

const (
	// CodeTLSNotAllocated: the image declares thread-local storage. The loader
	// does not allocate a TLS index, so a __declspec(thread) variable that relies
	// on being zero-initialised reads another module's slot instead. Measured: a
	// counter that should reach 3 came back -2147483645. The TLS callbacks do run
	// (the directory is read from the saved header copy); the index is what is
	// missing.
	CodeTLSNotAllocated CompatCode = "tls_index_not_allocated"

	// CodeTLSCallbacksOnly: the TLS directory declares callbacks but no static
	// template (StartAddressOfRawData == EndAddressOfRawData and SizeOfZeroFill
	// == 0). The loader runs the callbacks and there is no thread-local data to
	// zero-initialise, so the missing TLS index does not affect this image. This
	// is informational, not the CodeTLSNotAllocated warning.
	CodeTLSCallbacksOnly CompatCode = "tls_callbacks_only"

	// CodeNoRelocations: the image has no base relocation table, so it can only
	// run at its preferred image base. Nothing checks that the base was
	// actually granted.
	CodeNoRelocations CompatCode = "no_relocations"

	// CodeDelayImportsEager: delay-loaded imports are resolved up front, so the
	// lazy semantics (and any delay-load notification hook) are lost.
	CodeDelayImportsEager CompatCode = "delay_imports_resolved_eagerly"

	// CodeLoadConfigIgnored: a load configuration directory is present and
	// simply not read, so declared stack sizes, CFG settings and the x86 safe
	// exception handler table have no effect.
	CodeLoadConfigIgnored CompatCode = "load_config_ignored"

	// CodeGuardCFG: the image was built with control flow guard. The guard
	// function table is never registered, and because the OS never maps the
	// module it also never arms the image's dispatch pointer (measured: it stays
	// at the linker's internal no-op stub). Indirect calls therefore run
	// unvalidated; a /guard:cf payload was measured to run without a fast-fail,
	// so this is a security-posture warning, not a compatibility blocker.
	CodeGuardCFG CompatCode = "guard_cf_not_registered"

	// CodeNoEntryPoint: AddressOfEntryPoint is zero. For an EXE the loader would
	// jump to the image base (a blocker); for a DLL it skips DllMain and calls the
	// named export, which is legitimate for resource-only/export-only libraries
	// (informational).
	CodeNoEntryPoint CompatCode = "no_entry_point"

	// CodeRWXSection: a section is both writable and executable, which the
	// loader deliberately leaves as is.
	CodeRWXSection CompatCode = "rwx_section_kept"

	// CodeManagedAssembly: the image is a .NET assembly. Not generated at all.
	CodeManagedAssembly CompatCode = "managed_assembly"

	// CodeForwardedExport: an export's function RVA points inside the export
	// directory, which means it is a forwarder string ("OTHERDLL.Func") rather
	// than code. The loader resolves exports by address and would jump into that
	// string, so such an export cannot be called directly.
	CodeForwardedExport CompatCode = "forwarded_export"
)

// CompatIssue is one finding. Detail carries the concrete numbers that made the
// finding, so a report is self-explanatory in a log.
type CompatIssue struct {
	Code   CompatCode
	Level  CompatLevel
	Detail string
}

func (i CompatIssue) String() string {
	return fmt.Sprintf("%s [%s] %s", i.Code, i.Level, i.Detail)
}

// CompatIssues is a report that can be filtered by level.
type CompatIssues []CompatIssue

// Blockers returns only the issues that make the payload unusable.
func (is CompatIssues) Blockers() CompatIssues {
	var out CompatIssues
	for _, i := range is {
		if i.Level == CompatBlock {
			out = append(out, i)
		}
	}
	return out
}

// WarningsAtLeast returns issues at level or above.
func (is CompatIssues) WarningsAtLeast(level CompatLevel) CompatIssues {
	var out CompatIssues
	for _, i := range is {
		if i.Level >= level {
			out = append(out, i)
		}
	}
	return out
}

// Has returns true if the report contains the given code.
func (is CompatIssues) Has(code CompatCode) bool {
	for _, i := range is {
		if i.Code == code {
			return true
		}
	}
	return false
}

// Compat examines a payload and reports what the loader is known to handle
// poorly or not at all. It performs no allocation and never modifies payload.
//
// It returns ErrEmptyInput, ErrFileInvalid or ErrManagedImage for the inputs
// Build refuses anyway, so a caller can use Compat alone to sort a directory of
// candidates.
func Compat(payload []byte) (CompatIssues, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyInput
	}
	pe, err := parsePE(payload)
	if err != nil {
		return nil, err
	}

	dirs := pe.dataDirectories()
	if dirs == nil {
		return nil, fmt.Errorf("%w: no data directories", ErrFileInvalid)
	}

	var issues CompatIssues
	at := func(level CompatLevel, code CompatCode, format string, args ...any) {
		issues = append(issues, CompatIssue{Code: code, Level: level, Detail: fmt.Sprintf(format, args...)})
	}

	// .NET: refused by Build, reported here so callers can filter before building.
	if rva, _ := directory(dirs, dirEntryCOM); rva != 0 {
		at(CompatBlock, CodeManagedAssembly, "COM descriptor present; managed assemblies are not generated")
	}

	entry := binary.LittleEndian.Uint32(pe.optHdr[16:])
	if entry == 0 {
		isDLL := binary.LittleEndian.Uint16(pe.fileHdr[18:])&fileDLL != 0
		if isDLL {
			// A DLL with no entry point is legitimate (resource-only or
			// export-only libraries). The loader skips DllMain and runs the
			// named export, so this is not a blocker.
			at(CompatInfo, CodeNoEntryPoint,
				"AddressOfEntryPoint is 0; the loader skips DllMain for a DLL and calls the named export directly")
		} else {
			at(CompatBlock, CodeNoEntryPoint, "AddressOfEntryPoint is 0; the loader would jump to the image base")
		}
	}

	// Forwarded exports resolve to a "DLL.Func" string inside the export
	// directory, not to code. The loader calls exports by address, so it would
	// jump into that string. Report them; Build also refuses a forwarded Method.
	for _, f := range forwardedExports(payload, pe) {
		at(CompatWarning, CodeForwardedExport,
			"export %q is a forwarder (%s); the loader calls exports by address and would jump into the forwarder string",
			f.name, f.target)
	}

	// TLS. The loader runs the callbacks (the directory is read from the saved
	// header copy, not the mapped headers the default option wipes) but allocates
	// no static TLS index. That only matters when the image actually declares
	// thread-local data: a non-empty template (StartAddressOfRawData !=
	// EndAddressOfRawData) or a non-zero zero-fill. A callbacks-only directory has
	// no data to zero-initialise, so the missing index is harmless there and is
	// reported as information rather than a warning.
	if rva, size := directory(dirs, dirEntryTLS); rva != 0 {
		hasData, known := tlsHasStaticData(payload, pe, rva, size)
		switch {
		case known && !hasData:
			at(CompatInfo, CodeTLSCallbacksOnly,
				"TLS directory at rva 0x%x (%d bytes) declares callbacks but no static template "+
					"(empty raw-data range and zero zero-fill); callbacks run and no TLS index is needed",
				rva, size)
		case known && hasData:
			at(CompatWarning, CodeTLSNotAllocated,
				"TLS directory at rva 0x%x (%d bytes) declares thread-local data: callbacks run but no TLS index is allocated, "+
					"so __declspec(thread) data is not zero-initialised (measured: expected 3, observed -2147483645)",
				rva, size)
		default:
			// Could not read the directory fields; stay conservative and keep the
			// warning rather than silently downgrading an unverified image.
			at(CompatWarning, CodeTLSNotAllocated,
				"TLS directory at rva 0x%x (%d bytes): callbacks run but no TLS index is allocated, "+
					"so __declspec(thread) data is not zero-initialised (measured: expected 3, observed -2147483645)",
				rva, size)
		}
	}

	// Relocation situation.
	relocRVA, _ := directory(dirs, dirEntryBaseReloc)
	imageBase := imageBaseOf(pe)
	if relocRVA == 0 {
		at(CompatWarning, CodeNoRelocations,
			"no base relocation table; can only run at the preferred base 0x%x, and nothing verifies that it was granted",
			imageBase)
	}

	if rva, size := directory(dirs, dirEntryDelayImport); rva != 0 {
		at(CompatInfo, CodeDelayImportsEager,
			"delay-import table at rva 0x%x (%d bytes) is resolved eagerly, so lazy loading and any delay-load hooks are lost",
			rva, size)
	}

	if rva, size := directory(dirs, dirEntryLoadConfig); rva != 0 {
		at(CompatWarning, CodeLoadConfigIgnored,
			"load config directory at rva 0x%x (%d bytes) is not read: declared stack sizes, CFG settings and the safe exception handler table have no effect",
			rva, size)

		// Guard flags live inside the load config; read them when the structure
		// is big enough to contain them, so CFG can be reported precisely
		// instead of guessed from DllCharacteristics alone. GuardFlags sits at
		// different offsets in the 32- and 64-bit layouts, so pick by machine.
		// Bound the read by the structure's own Size field and the directory
		// size, not by how much file happens to follow: a smaller/older load
		// config must not be read past its end into whatever comes next.
		if off := rvaToOffset(payload, pe, rva); off >= 0 {
			cfg := payload[off:]
			guardOff := loadCfg64GuardFlags
			if pe.is32 {
				guardOff = loadCfg32GuardFlags
			}
			if len(cfg) >= guardOff+4 {
				cfgSize := uint64(binary.LittleEndian.Uint32(cfg)) // IMAGE_LOAD_CONFIG_DIRECTORY*.Size
				limit := uint64(len(cfg))
				if size != 0 && uint64(size) < limit {
					limit = uint64(size)
				}
				if cfgSize >= uint64(guardOff+4) && uint64(guardOff+4) <= limit {
					guard := binary.LittleEndian.Uint32(cfg[guardOff:])
					if guard&imageGuardCFTablePresent != 0 {
						at(CompatWarning, CodeGuardCFG,
							"IMAGE_GUARD_CF is set in the load config (GuardFlags=0x%x) but the guard function table is never registered; "+
								"measured: the image's dispatch pointer stays at its internal no-op stub, so indirect calls run unvalidated "+
								"(no fast-fail observed)",
							guard)
					}
				}
			}
		}
	} else if pe.dllCharacteristics()&imageDllCharacteristicsGuardCF != 0 {
		at(CompatWarning, CodeGuardCFG,
			"DllCharacteristics advertises GUARD_CF without a load config to describe it; indirect calls are not validated")
	}

	for i := 0; i < pe.numberOfSections(); i++ {
		va, raw, _ := pe.section(i)
		_ = raw
		chars := sectionCharacteristics(pe, i)
		if chars&imageScnMemWrite != 0 && chars&imageScnMemExecute != 0 {
			at(CompatInfo, CodeRWXSection, "section at rva 0x%x is writable and executable and stays that way", va)
		}
	}

	return issues, nil
}

// tlsHasStaticData reports whether the TLS directory declares thread-local data
// (a non-empty raw-data template or a non-zero zero-fill), as opposed to callbacks
// only. known is false when the directory cannot be read far enough to decide, in
// which case the caller keeps the conservative warning.
func tlsHasStaticData(data []byte, pe *peHeaders, rva, size uint32) (hasData, known bool) {
	startOff, endOff, zeroOff := tls64StartAddressOfRawData, tls64EndAddressOfRawData, tls64SizeOfZeroFill
	ptrSize := 8
	if pe.is32 {
		startOff, endOff, zeroOff = tls32StartAddressOfRawData, tls32EndAddressOfRawData, tls32SizeOfZeroFill
		ptrSize = 4
	}
	off := rvaToOffset(data, pe, rva)
	if off < 0 {
		return false, false
	}
	dir := data[off:]
	// Bound by the directory size when it is meaningful, and always by the file.
	limit := uint64(len(dir))
	if size != 0 && uint64(size) < limit {
		limit = uint64(size)
	}
	if uint64(zeroOff+4) > limit || uint64(endOff+ptrSize) > limit {
		return false, false
	}
	var start, end uint64
	if pe.is32 {
		start = uint64(binary.LittleEndian.Uint32(dir[startOff:]))
		end = uint64(binary.LittleEndian.Uint32(dir[endOff:]))
	} else {
		start = binary.LittleEndian.Uint64(dir[startOff:])
		end = binary.LittleEndian.Uint64(dir[endOff:])
	}
	zeroFill := binary.LittleEndian.Uint32(dir[zeroOff:])
	return start != end || zeroFill != 0, true
}

// forwarder is one exported name whose function RVA is a forwarder string.
type forwarder struct {
	name   string
	target string
}

// forwardedExports enumerates exports whose function RVA falls inside the export
// directory, i.e. forwarder strings rather than code. It reads only what the file
// bounds allow and skips anything malformed.
func forwardedExports(data []byte, pe *peHeaders) []forwarder {
	exportRVA, exportSize := pe.directory(dirEntryExport)
	if exportRVA == 0 || exportSize == 0 {
		return nil
	}
	off := rvaToOffset(data, pe, exportRVA)
	if off < 0 || off+40 > int64(len(data)) {
		return nil
	}
	exp := data[off:]
	numberOfNames := binary.LittleEndian.Uint32(exp[24:])
	numberOfFunctions := binary.LittleEndian.Uint32(exp[20:])
	addressOfNames := binary.LittleEndian.Uint32(exp[32:])
	addressOfNameOrdinals := binary.LittleEndian.Uint32(exp[36:])
	addressOfFunctions := binary.LittleEndian.Uint32(exp[28:])

	namesOff := rvaToOffset(data, pe, addressOfNames)
	ordsOff := rvaToOffset(data, pe, addressOfNameOrdinals)
	funcsOff := rvaToOffset(data, pe, addressOfFunctions)
	if namesOff < 0 || ordsOff < 0 || funcsOff < 0 {
		return nil
	}
	if namesOff+int64(numberOfNames)*4 > int64(len(data)) ||
		ordsOff+int64(numberOfNames)*2 > int64(len(data)) {
		return nil
	}

	var out []forwarder
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
		name := string(data[nameOff : int64(nameOff)+int64(end)])

		ordinal := uint32(binary.LittleEndian.Uint16(data[ordsOff+int64(i)*2:]))
		if ordinal >= numberOfFunctions {
			continue
		}
		if funcsOff+int64(ordinal)*4+4 > int64(len(data)) {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(data[funcsOff+int64(ordinal)*4:])
		// A forwarder's RVA points inside the export directory itself.
		if funcRVA < exportRVA || funcRVA-exportRVA >= exportSize {
			continue
		}
		target := ""
		if foff := rvaToOffset(data, pe, funcRVA); foff >= 0 && foff < int64(len(data)) {
			if e := indexByte(data[foff:], 0); e >= 0 {
				target = string(data[foff : int64(foff)+int64(e)])
			}
		}
		out = append(out, forwarder{name: name, target: target})
	}
	return out
}

// isForwardedExport reports whether the named export is a forwarder. Build uses it
// to refuse a Method the loader could not call by address.
func isForwardedExport(data []byte, pe *peHeaders, name string) bool {
	for _, f := range forwardedExports(data, pe) {
		if f.name == name {
			return true
		}
	}
	return false
}
