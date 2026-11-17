package test

import (
	"errors"
	"testing"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

// Enhancement #4 (Go side): a DLL with no entry point is legitimate and must not
// be a blocker; an EXE with no entry point still is.

func TestCompatNoEntryDLLIsInfo(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		p := newSyntheticPE(is32, true, 0) // DLL, entry 0
		p.addExports([]string{"RunIt"})
		issues, err := donut.Compat(p.data)
		if err != nil {
			t.Fatalf("Compat (is32=%v): %v", is32, err)
		}
		if len(issues.Blockers()) != 0 {
			t.Fatalf("is32=%v: entry-less DLL must have no blockers; got %v", is32, issues.Blockers())
		}
		var found bool
		for _, i := range issues {
			if string(i.Code) == "no_entry_point" {
				found = true
				if i.Level != donut.CompatInfo {
					t.Fatalf("is32=%v: no_entry_point should be info for a DLL, got %v", is32, i.Level)
				}
			}
		}
		if !found {
			t.Fatalf("is32=%v: expected a no_entry_point info finding; got %v", is32, issues)
		}
	}
}

func TestCompatNoEntryEXEIsBlock(t *testing.T) {
	p := newSyntheticPE(false, false, 0) // EXE, entry 0
	issues, err := donut.Compat(p.data)
	if err != nil {
		t.Fatalf("Compat: %v", err)
	}
	if !issues.Has("no_entry_point") {
		t.Fatalf("entry-less EXE should report no_entry_point; got %v", issues)
	}
	if len(issues.Blockers()) == 0 {
		t.Fatalf("entry-less EXE must be a blocker; got %v", issues)
	}
}

func TestBuildStrictAcceptsNoEntryDLL(t *testing.T) {
	p := newSyntheticPE(false, true, 0)
	p.addExports([]string{"RunIt"})
	cfg := donut.DefaultConfig(p.data)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Strict = true
	cfg.Method = "RunIt"
	if _, err := donut.Build(cfg); err != nil {
		t.Fatalf("Strict build of entry-less DLL with export should succeed, got %v", err)
	}
}

func TestBuildStrictRejectsNoEntryEXE(t *testing.T) {
	p := newSyntheticPE(false, false, 0)
	cfg := donut.DefaultConfig(p.data)
	cfg.Arch = donut.ArchX64
	cfg.Entropy = donut.EntropyNone
	cfg.Strict = true
	_, err := donut.Build(cfg)
	if !errors.Is(err, donut.ErrIncompatiblePayload) {
		t.Fatalf("Strict build of entry-less EXE should be refused, got %v", err)
	}
}