package test

import (
	"errors"
	"strings"
	"testing"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

// SDK GuardFlags offsets, restated independently of the library constants.
const (
	guardFlagsOff32 = 88  // IMAGE_LOAD_CONFIG_DIRECTORY32.GuardFlags
	guardFlagsOff64 = 144 // IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags
	cfTablePresent  = 0x00000400
)

func hasGuardCFG(issues donut.CompatIssues) bool {
	return issues.Has("guard_cf_not_registered")
}

// --- Fix 1: GuardFlags offset must follow the image bitness -------------------

func TestGuardCFGDetectedX64(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addLoadConfig(192, 192, guardFlagsOff64, cfTablePresent, 0)
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if !hasGuardCFG(issues) {
		t.Fatalf("x64 load config with CF table present should report guard_cf_not_registered; got %v", issues)
	}
}

func TestGuardCFGDetectedX86(t *testing.T) {
	p := newSyntheticPE(true, true, 0x1000)
	p.addLoadConfig(128, 128, guardFlagsOff32, cfTablePresent, 0)
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if !hasGuardCFG(issues) {
		t.Fatalf("x86 load config with CF table present should report guard_cf_not_registered; got %v", issues)
	}
}

// The regression itself: an x86 image whose GuardFlags (offset 88) is clean but
// whose offset 144 holds a pointer with bit 0x400 set. Reading offset 144 (the
// 64-bit offset, wrong for x86) would falsely report CFG.
func TestGuardCFGNoFalsePositiveX86(t *testing.T) {
	p := newSyntheticPE(true, true, 0x1000)
	p.addLoadConfig(176, 176, guardFlagsOff32, 0, 0)
	p.putU32(sectionRVA+144, 0x00000400) // GuardRFVerifyStackPointerFunctionPointer low dword
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if hasGuardCFG(issues) {
		t.Fatalf("x86 image with clean GuardFlags must not report CFG from offset 144; got %v", issues)
	}
}

// --- Fix 2: bound the read by the structure Size and the directory size -------

// A small/older load config (Size below the GuardFlags field) with a CF-looking
// dword sitting past its declared end must not be read.
func TestGuardCFGRespectsStructSize(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		guardOff := guardFlagsOff64
		if is32 {
			guardOff = guardFlagsOff32
		}
		p := newSyntheticPE(is32, true, 0x1000)
		// Size=64 (< guardOff+4), directory size 64, but a CF dword at guardOff.
		p.addLoadConfig(64, 64, guardOff, cfTablePresent, 0)
		issues, err := donut.Compat(p.data)
		if err != nil {
			t.Fatalf("Compat (is32=%v): %v", is32, err)
		}
		if hasGuardCFG(issues) {
			t.Fatalf("is32=%v: load config Size=64 must not expose GuardFlags at %d; got %v", is32, guardOff, issues)
		}
	}
}

// The directory size can be smaller than the structure Size; the smaller bound
// wins. Here Size is large but the directory advertises only 64 bytes.
func TestGuardCFGRespectsDirectorySize(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addLoadConfig(192, 64, guardFlagsOff64, cfTablePresent, 0)
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if hasGuardCFG(issues) {
		t.Fatalf("directory size 64 must bound the read below GuardFlags; got %v", issues)
	}
}

// A full-size structure with the CF bit genuinely set is still reported (the
// bounds must not suppress a real finding).
func TestGuardCFGFullSizeStillReported(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addLoadConfig(256, 256, guardFlagsOff64, cfTablePresent, 64)
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if !hasGuardCFG(issues) {
		t.Fatalf("full-size load config with CF bit set should still be reported; got %v", issues)
	}
}

// --- Fix 3: an over-long export name is refused at Build ----------------------

func dllWithExport(t *testing.T, name string) []byte {
	t.Helper()
	p := newSyntheticPE(false, true, 0x1000)
	p.addExports([]string{name})
	return p.data
}

func TestBuildRejectsOverlongMethod(t *testing.T) {
	long := strings.Repeat("A", donut.MaxNameLen+1)
	payload := dllWithExport(t, long)

	// Sanity: the export really exists, so the only reason to refuse is length.
	cfg := donut.DefaultConfig(payload)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = long
	_, err := donut.Build(cfg)
	if !errors.Is(err, donut.ErrMethodNameTooLong) {
		t.Fatalf("over-long Method should return ErrMethodNameTooLong, got %v", err)
	}
}

func TestBuildAcceptsMaxLengthMethod(t *testing.T) {
	name := strings.Repeat("B", donut.MaxNameLen) // exactly 255, fits
	payload := dllWithExport(t, name)
	cfg := donut.DefaultConfig(payload)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = name
	pic, err := donut.Build(cfg)
	if err != nil {
		t.Fatalf("Method of exactly MaxNameLen should build, got %v", err)
	}
	if len(pic) == 0 {
		t.Fatal("Build returned empty shellcode")
	}
	got, ok := donut.ModuleString(pic, donut.ModuleMethodOffset)
	if !ok || got != name {
		t.Fatalf("stored method = %q (ok=%v), want the full %d-byte name", got, ok, len(name))
	}
}

func TestBuildShortMethodStillWorks(t *testing.T) {
	payload := dllWithExport(t, "RunIt")
	cfg := donut.DefaultConfig(payload)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = "RunIt"
	cfg.Args = "--verbose"
	if _, err := donut.Build(cfg); err != nil {
		t.Fatalf("normal short Method should build, got %v", err)
	}
}

// A name that fits the field but is not exported must still fail with the
// existing export error (the length check must not shadow it).
func TestBuildUnknownMethodStillExportError(t *testing.T) {
	payload := dllWithExport(t, "RunIt")
	cfg := donut.DefaultConfig(payload)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = "DoesNotExist"
	_, err := donut.Build(cfg)
	if !errors.Is(err, donut.ErrDLLFunction) {
		t.Fatalf("unknown export should return ErrDLLFunction, got %v", err)
	}
}