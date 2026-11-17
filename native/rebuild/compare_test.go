package donut

import (
	"bytes"
	"testing"

	lib "github.com/B1gCheater/shellcode-lib-go/donut"
)

// The rebuilt blobs (exe2h output, package donut) are compiled into this test
// binary alongside the library. We compare them against the enhanced blobs the
// library actually embeds, by generating two EntropyNone shellcodes that differ
// only in the loader tail and diffing the tail region.
//
// This is a feasibility check: byte identity is NOT expected across compiler
// versions (the stored blobs came from a different toolchain). What matters is
// that the rebuild pipeline produces a structurally equivalent loader of
// comparable size, proving the blobs can be regenerated from source + patch.

func tailOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	cfg := lib.DefaultConfig(payload)
	cfg.Arch = lib.ArchX64
	cfg.Entropy = lib.EntropyNone
	cfg.Bypass = lib.BypassNone
	pic, err := lib.Build(cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// layout: [5 prologue][instance+module blob][1 pop ecx][22 RSP align][loader]
	// instance len = InstanceSize + module header + payload
	instLen := lib.InstanceSize + lib.ModuleHeaderSize + len(payload)
	start := lib.PrologueLen + instLen + 1 + 22
	if start >= len(pic) {
		t.Fatalf("tail start %d beyond pic len %d", start, len(pic))
	}
	return pic[start:]
}

func TestRebuildX64Comparable(t *testing.T) {
	// A valid synthetic PE; the loader tail is payload-independent.
	payload := newSyntheticPE(false, true, 0x1000).data
	stored := tailOf(t, payload)
	rebuilt := LOADER64_OS_EXE_X64

	t.Logf("stored x64 loader tail: %d bytes", len(stored))
	t.Logf("rebuilt x64 loader:     %d bytes", len(rebuilt))

	if len(rebuilt) == 0 {
		t.Fatal("rebuilt x64 blob is empty")
	}
	// Size sanity: the enhanced loader is ~13 KB; allow a wide band for toolchain
	// differences but reject a trivially wrong extraction.
	if len(rebuilt) < 4096 || len(rebuilt) > 65536 {
		t.Fatalf("rebuilt x64 size %d outside plausible loader range", len(rebuilt))
	}
	if bytes.Equal(stored, rebuilt) {
		t.Log("BYTE-IDENTICAL: rebuild reproduces the stored enhanced loader exactly")
	} else {
		// Report how much overlaps from the start (shared prologue / early code).
		n := 0
		for n < len(stored) && n < len(rebuilt) && stored[n] == rebuilt[n] {
			n++
		}
		t.Logf("not byte-identical (expected across toolchains); common prefix = %d bytes", n)
	}
}