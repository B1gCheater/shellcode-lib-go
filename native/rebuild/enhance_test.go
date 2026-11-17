package donut

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Enhancement-specific behavioural tests. These run the REBUILT (enhanced)
// loader against purpose-built payloads and assert the new behaviour. They skip
// if the verification artefacts have not been built (verify/build.ps1).

func runCmd(t *testing.T, name string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		code = -999
	}
	return out.String(), code
}

func genRebuilt(t *testing.T, vdir, pe, arch, method, blob, prefix string) {
	t.Helper()
	gen := filepath.Join(vdir, "gen.exe")
	out, code := runCmd(t, gen, "-in", filepath.Join(vdir, pe), "-out", prefix,
		"-arch", arch, "-method", method, "-rebuilt", filepath.Join(vdir, blob))
	if code != 0 {
		t.Fatalf("gen failed (%d): %s", code, out)
	}
}

// Enhancement #4: a DLL with AddressOfEntryPoint == 0 must run its export. The
// stored (pre-enhancement) loader crashes on such an image; the rebuilt one must
// skip DllMain and call the export.
func TestEnhancedNoEntryDLL(t *testing.T) {
	wd, _ := os.Getwd()
	vdir := filepath.Join(wd, "verify")
	cases := []struct {
		name, pe, arch, blob, runner string
	}{
		{"x64", "payload_noentry64.dll", "x64", "loader64_os_exe_x64.bin", "runner.exe"},
		{"x86", "payload_noentry32.dll", "x86", "loader32_os_exe_x86.bin", "runner32.exe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range []string{tc.pe, tc.blob, tc.runner, "gen.exe"} {
				if _, err := os.Stat(filepath.Join(vdir, f)); err != nil {
					t.Skipf("artefact %s missing; run verify/build.ps1", f)
				}
			}
			prefix := filepath.Join(vdir, "sc_noentry_"+tc.name)
			genRebuilt(t, vdir, tc.pe, tc.arch, "RunIt", tc.blob, prefix)

			// Rebuilt (enhanced): must print the marker and return cleanly.
			out, code := runCmd(t, filepath.Join(vdir, tc.runner), prefix+".rebuilt.bin")
			if code != 0 || !strings.Contains(out, "PAYLOAD_NOENTRY run") {
				t.Fatalf("enhanced loader should run entry-less DLL export; exit=%d out:\n%s", code, out)
			}
			if !strings.Contains(out, "RUNNER_OK") {
				t.Fatalf("enhanced loader should return to runner; out:\n%s", out)
			}

			// Stored (pre-enhancement): expected to crash (calls the image base).
			sout, scode := runCmd(t, filepath.Join(vdir, tc.runner), prefix+".stored.bin")
			t.Logf("stored loader on entry-less DLL: exit=%d (expected crash), markers=%v",
				scode, strings.Contains(sout, "PAYLOAD_NOENTRY"))
			if scode == 0 && strings.Contains(sout, "PAYLOAD_NOENTRY run") {
				t.Logf("note: stored loader also handled it (unexpected but not a failure)")
			}
		})
	}
}

// Enhancements #1/#2/#3: repeated loads in one host must not leak executable
// private pages (the pc2f stub is freed) and must leave the host usable. The
// stored loader leaks one RWX page per load; the rebuilt one must leak zero.
func TestEnhancedCleanupNoLeak(t *testing.T) {
	wd, _ := os.Getwd()
	vdir := filepath.Join(wd, "verify")
	for _, f := range []string{"payload_dll64.dll", "loader64_os_exe_x64.bin", "runner_loop.exe", "gen.exe"} {
		if _, err := os.Stat(filepath.Join(vdir, f)); err != nil {
			t.Skipf("artefact %s missing; run verify/build.ps1", f)
		}
	}
	prefix := filepath.Join(vdir, "sc_cleanup_x64")
	genRebuilt(t, vdir, "payload_dll64.dll", "x64", "RunIt", "loader64_os_exe_x64.bin", prefix)

	delta := func(blob string) int {
		out, code := runCmd(t, filepath.Join(vdir, "runner_loop.exe"), blob, "10")
		if code != 0 {
			t.Fatalf("runner_loop failed (%d): %s", code, out)
		}
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "EXEC_PRIVATE_DELTA ") {
				n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ln, "EXEC_PRIVATE_DELTA")))
				return n
			}
		}
		t.Fatalf("no EXEC_PRIVATE_DELTA in output:\n%s", out)
		return 0
	}

	rebuiltDelta := delta(prefix + ".rebuilt.bin")
	storedDelta := delta(prefix + ".stored.bin")
	t.Logf("executable-private page delta over 10 loads: rebuilt=%d stored=%d", rebuiltDelta, storedDelta)

	if rebuiltDelta != 0 {
		t.Fatalf("enhanced loader leaked %d executable private pages over 10 loads; want 0", rebuiltDelta)
	}
	if storedDelta <= 0 {
		t.Logf("note: stored loader delta=%d (expected >0 leak); cleanup enhancement still verified by rebuilt=0", storedDelta)
	}
}