// Command gen produces shellcode variants for behavioural verification.
//
// For each input PE it writes:
//
//	<out>.stored.bin    Build output using the library's embedded enhanced loader
//	<out>.rebuilt.bin   the same instance with the loader tail swapped for a
//	                    rebuilt blob (from source + patch)
//
// The instance (prologue + DONUT_INSTANCE + module) is loader-independent, so
// swapping only the tail isolates the loader as the single variable.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

func main() {
	in := flag.String("in", "", "input PE file")
	out := flag.String("out", "", "output prefix")
	arch := flag.String("arch", "x64", "x64 or x86")
	method := flag.String("method", "", "DLL export to call")
	args := flag.String("args", "", "argument string to pass")
	rebuilt := flag.String("rebuilt", "", "rebuilt loader blob file (raw .text)")
	flag.Parse()

	if *in == "" || *out == "" || *rebuilt == "" {
		fmt.Fprintln(os.Stderr, "need -in, -out, -rebuilt")
		os.Exit(2)
	}

	payload, err := os.ReadFile(*in)
	must(err)
	blob, err := os.ReadFile(*rebuilt)
	must(err)

	cfg := donut.DefaultConfig(payload)
	cfg.Entropy = donut.EntropyNone
	cfg.Bypass = donut.BypassNone
	cfg.Headers = donut.HeadersKeep
	cfg.ExitOpt = donut.ExitThread
	cfg.Compress = donut.CompressNone
	cfg.Method = *method
	cfg.Args = *args

	x64 := *arch == "x64"
	if x64 {
		cfg.Arch = donut.ArchX64
	} else {
		cfg.Arch = donut.ArchX86
	}

	pic, err := donut.Build(cfg)
	must(err)
	must(os.WriteFile(*out+".stored.bin", pic, 0o644))

	// Locate the loader tail. Layout:
	//   [5 prologue][instance+module][1 pop ecx][arch preamble][loader][pad]
	instLen := donut.InstanceSize + donut.ModuleHeaderSize + len(payload)
	// Cross-check against the instance's own len field (offset 0 of the instance).
	if got := binary.LittleEndian.Uint32(pic[donut.PrologueLen:]); int(got) != instLen {
		fmt.Fprintf(os.Stderr, "instance len mismatch: computed %d, field %d\n", instLen, got)
		os.Exit(1)
	}
	tailStart := donut.PrologueLen + instLen + 1 // after pop ecx
	var preamble int
	if x64 {
		preamble = 22 // x64 RSP-align prologue
	} else {
		preamble = 3 // pop edx; push ecx; push edx
	}
	loaderStart := tailStart + preamble

	// Rebuilt shellcode = instance + pop ecx + preamble + rebuilt loader.
	// (The trailing zero pad is never executed; omit it.)
	out2 := make([]byte, 0, loaderStart+len(blob))
	out2 = append(out2, pic[:loaderStart]...)
	out2 = append(out2, blob...)
	must(os.WriteFile(*out+".rebuilt.bin", out2, 0o644))

	fmt.Printf("stored=%d rebuilt=%d loaderStart=%d\n", len(pic), len(out2), loaderStart)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}