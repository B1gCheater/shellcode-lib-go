package donut

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Behavioural verification: run the same payload under the stored enhanced loader
// and under a rebuilt loader (source + patch, this toolchain), in isolated child
// processes with a timeout, and compare what they print.
//
// Paths are resolved relative to this test's directory (native/rebuild).

func rebuildDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func runBlob(t *testing.T, runner, blob string) (string, int, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runner, blob)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	timedOut := ctx.Err() == context.DeadlineExceeded
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return out.String(), code, timedOut
}

// payloadMarkers extracts the PAYLOAD_* lines (the payload's own output),
// ignoring runner diagnostics, so the comparison is about payload behaviour.
func payloadMarkers(s string) []string {
	var lines []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "PAYLOAD_") {
			lines = append(lines, ln)
		}
	}
	return lines
}

func TestBehaviourStoredVsRebuilt(t *testing.T) {
	dir := rebuildDir(t)
	vdir := filepath.Join(dir, "verify")
	runner64 := filepath.Join(vdir, "runner.exe")
	runner32 := filepath.Join(vdir, "runner32.exe")
	gen := filepath.Join(vdir, "gen.exe")

	for _, p := range []string{runner64, runner32, gen} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("verification artefact missing (%s); build it first: %v", p, err)
		}
	}

	cases := []struct {
		name    string
		pe      string
		arch    string
		method  string
		blob    string
		wantMark string
	}{
		{"exe_x64", "payload_exe64.exe", "x64", "", "loader64_os_exe_x64.bin", "PAYLOAD_EXE sum=5050"},
		{"dll_x64", "payload_dll64.dll", "x64", "RunIt", "loader64_os_exe_x64.bin", "PAYLOAD_DLL run sum=5050"},
		{"exe_x86", "payload_exe32.exe", "x86", "", "loader32_os_exe_x86.bin", "PAYLOAD_EXE sum=5050"},
		{"dll_x86", "payload_dll32.dll", "x86", "RunIt", "loader32_os_exe_x86.bin", "PAYLOAD_DLL run sum=5050"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := filepath.Join(vdir, tc.pe)
			blob := filepath.Join(vdir, tc.blob)
			for _, p := range []string{pe, blob} {
				if _, err := os.Stat(p); err != nil {
					t.Skipf("missing %s: %v", p, err)
				}
			}
			prefix := filepath.Join(vdir, "sc_"+tc.name)
			gencmd := exec.Command(gen, "-in", pe, "-out", prefix, "-arch", tc.arch,
				"-method", tc.method, "-rebuilt", blob)
			if gout, err := gencmd.CombinedOutput(); err != nil {
				t.Fatalf("gen failed: %v\n%s", err, gout)
			}

			runner := runner64
			if tc.arch == "x86" {
				runner = runner32
			}
			storedOut, storedCode, storedTO := runBlob(t, runner, prefix+".stored.bin")
			rebuiltOut, rebuiltCode, rebuiltTO := runBlob(t, runner, prefix+".rebuilt.bin")

			t.Logf("stored : exit=%d timeout=%v markers=%v", storedCode, storedTO, payloadMarkers(storedOut))
			t.Logf("rebuilt: exit=%d timeout=%v markers=%v", rebuiltCode, rebuiltTO, payloadMarkers(rebuiltOut))

			if storedTO || rebuiltTO {
				t.Fatalf("a variant timed out (stored=%v rebuilt=%v); full output:\nSTORED:\n%s\nREBUILT:\n%s",
					storedTO, rebuiltTO, storedOut, rebuiltOut)
			}

			sm := payloadMarkers(storedOut)
			rm := payloadMarkers(rebuiltOut)
			if len(sm) == 0 {
				t.Fatalf("stored loader produced no payload marker; output:\n%s", storedOut)
			}
			// The rebuilt loader must reproduce the payload's behaviour.
			if strings.Join(sm, "|") != strings.Join(rm, "|") {
				t.Fatalf("behaviour differs:\n stored markers=%v\n rebuilt markers=%v\nSTORED:\n%s\nREBUILT:\n%s",
					sm, rm, storedOut, rebuiltOut)
			}
			if !strings.Contains(strings.Join(rm, "|"), tc.wantMark) {
				t.Fatalf("rebuilt markers %v missing expected %q", rm, tc.wantMark)
			}
			// Both should return cleanly to the runner (ExitThread).
			if !strings.Contains(storedOut, "RUNNER_OK") || !strings.Contains(rebuiltOut, "RUNNER_OK") {
				t.Logf("note: not both returned RUNNER_OK (stored exit=%d rebuilt exit=%d)", storedCode, rebuiltCode)
			}
		})
	}
}