package test

import (
	"testing"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

func issueLevel(issues donut.CompatIssues, code string) (donut.CompatLevel, bool) {
	for _, i := range issues {
		if string(i.Code) == code {
			return i.Level, true
		}
	}
	return 0, false
}

// --- Fix 5: TLS callbacks-only vs static data ---------------------------------

// A TLS directory with an empty template and zero zero-fill is callbacks-only:
// the missing index is harmless, so it must be Info, not the Warning.
func TestTLSCallbacksOnlyIsInfo(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		p := newSyntheticPE(is32, true, 0x1000)
		p.addTLS(0, 0, 0) // start == end, zeroFill == 0
		issues, err := donut.Compat(p.data)
		if err != nil {
			t.Fatalf("Compat (is32=%v): %v", is32, err)
		}
		if issues.Has("tls_index_not_allocated") {
			t.Fatalf("is32=%v: callbacks-only TLS must not raise tls_index_not_allocated; got %v", is32, issues)
		}
		lvl, ok := issueLevel(issues, "tls_callbacks_only")
		if !ok || lvl != donut.CompatInfo {
			t.Fatalf("is32=%v: want tls_callbacks_only at info, got ok=%v lvl=%v (%v)", is32, ok, lvl, issues)
		}
	}
}

// A non-empty raw-data template means real thread-local data: keep the Warning.
func TestTLSWithTemplateKeepsWarning(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		p := newSyntheticPE(is32, true, 0x1000)
		p.addTLS(0x140001000, 0x140001010, 0) // start != end
		issues, err := donut.Compat(p.data)
		if err != nil {
			t.Fatalf("Compat (is32=%v): %v", is32, err)
		}
		lvl, ok := issueLevel(issues, "tls_index_not_allocated")
		if !ok || lvl != donut.CompatWarning {
			t.Fatalf("is32=%v: template TLS must keep tls_index_not_allocated warning, got ok=%v lvl=%v (%v)", is32, ok, lvl, issues)
		}
		if issues.Has("tls_callbacks_only") {
			t.Fatalf("is32=%v: template TLS must not be reported callbacks-only", is32)
		}
	}
}

// Empty template but a non-zero zero-fill still means thread-local data.
func TestTLSWithZeroFillKeepsWarning(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addTLS(0, 0, 16) // start == end but zeroFill != 0
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	lvl, ok := issueLevel(issues, "tls_index_not_allocated")
	if !ok || lvl != donut.CompatWarning {
		t.Fatalf("zero-fill TLS must keep the warning, got ok=%v lvl=%v (%v)", ok, lvl, issues)
	}
}

// --- Fix 6: forwarded exports -------------------------------------------------

func TestCompatReportsForwardedExport(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addForwardedExport("RunIt", "OTHERDLL.RealRun")
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	lvl, ok := issueLevel(issues, "forwarded_export")
	if !ok || lvl != donut.CompatInfo {
		t.Fatalf("forwarded export should be reported at info (resolved at run time), got ok=%v lvl=%v (%v)", ok, lvl, issues)
	}
}

// A forwarded Method must now build: the loader resolves it through the target
// module at run time instead of jumping into the forwarder string.
func TestBuildAcceptsForwardedMethod(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addForwardedExport("RunIt", "OTHERDLL.RealRun")
	cfg := donut.DefaultConfig(p.data)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = "RunIt"
	if _, err := donut.Build(cfg); err != nil {
		t.Fatalf("forwarded Method should now build (loader resolves it), got %v", err)
	}
}

// A normal (non-forwarded) export must still build — the forwarder check must not
// catch real code exports.
func TestBuildNormalExportNotForwarder(t *testing.T) {
	p := newSyntheticPE(false, true, 0x1000)
	p.addExports([]string{"RunIt"})
	cfg := donut.DefaultConfig(p.data)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Method = "RunIt"
	if _, err := donut.Build(cfg); err != nil {
		t.Fatalf("normal export should build, got %v", err)
	}
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if issues.Has("forwarded_export") {
		t.Fatalf("normal export must not be reported as forwarded; got %v", issues)
	}
}