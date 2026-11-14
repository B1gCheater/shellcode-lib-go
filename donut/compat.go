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

	// CodeNoEntryPoint: AddressOfEntryPoint is zero, so the loader would jump to
	// the image base itself.
	CodeNoEntryPoint CompatCode = "no_entry_point"

	// CodeRWXSection: a section is both writable and executable, which the
	// loader deliberately leaves as is.
	CodeRWXSection CompatCode = "rwx_section_kept"

	// CodeManagedAssembly: the image is a .NET assembly. Not generated at all.
	CodeManagedAssembly CompatCode = "managed_assembly"
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
		at(CompatBlock, CodeNoEntryPoint, "AddressOfEntryPoint is 0; the loader would jump to the image base")
	}

	// TLS. The loader does not allocate a TLS index, so thread-local variables
	// that rely on zero-initialisation read another module's slot. The callbacks
	// do run: the directory is read from the saved header copy, not the mapped
	// headers that the default option wipes.
	if rva, size := directory(dirs, dirEntryTLS); rva != 0 {
		at(CompatWarning, CodeTLSNotAllocated,
			"TLS directory at rva 0x%x (%d bytes): callbacks run but no TLS index is allocated, "+
				"so __declspec(thread) data is not zero-initialised (measured: expected 3, observed -2147483645)",
			rva, size)
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
		// instead of guessed from DllCharacteristics alone.
		if off := rvaToOffset(payload, pe, rva); off >= 0 {
			cfg := payload[off:]
			if len(cfg) >= loadCfg64GuardFlags+4 {
				guard := binary.LittleEndian.Uint32(cfg[loadCfg64GuardFlags:])
				if guard&imageGuardCFTablePresent != 0 {
					at(CompatWarning, CodeGuardCFG,
						"IMAGE_GUARD_CF is set in the load config (GuardFlags=0x%x) but the guard function table is never registered; "+
							"measured: the image's dispatch pointer stays at its internal no-op stub, so indirect calls run unvalidated "+
							"(no fast-fail observed)",
						guard)
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
