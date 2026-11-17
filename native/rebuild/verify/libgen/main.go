// libgen calls the library's public Build API to produce shellcode, for use by
// the standalone C / Python loaders. This exercises the real library path
// (DefaultConfig + Build), not a hand-assembled instance.
//
// Usage: libgen -in <pe> -out <bin> [-arch x64|x86] [-method name] [-args str]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/B1gCheater/shellcode-lib-go/donut"
)

func main() {
	in := flag.String("in", "", "input PE")
	out := flag.String("out", "", "output shellcode bin")
	arch := flag.String("arch", "x64", "x64 or x86")
	method := flag.String("method", "", "DLL export")
	args := flag.String("args", "", "arguments")
	entropy := flag.Int("entropy", donut.EntropyNone, "1=none 2=random 3=default")
	flag.Parse()
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "need -in and -out")
		os.Exit(2)
	}
	payload, err := os.ReadFile(*in)
	must(err)

	cfg := donut.DefaultConfig(payload)
	if *arch == "x86" {
		cfg.Arch = donut.ArchX86
	} else {
		cfg.Arch = donut.ArchX64
	}
	cfg.Method = *method
	cfg.Args = *args
	cfg.Entropy = *entropy
	cfg.Bypass = donut.BypassNone
	cfg.Headers = donut.HeadersKeep
	cfg.ExitOpt = donut.ExitThread

	pic, err := donut.Build(cfg)
	must(err)
	must(os.WriteFile(*out, pic, 0o644))
	fmt.Printf("libgen: wrote %d bytes to %s (arch=%s method=%q entropy=%d)\n",
		len(pic), *out, *arch, *method, *entropy)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "libgen error:", err)
		os.Exit(1)
	}
}