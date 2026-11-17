//go:build ignore

// blob2bin converts an exe2h-generated Go byte-array file into a raw binary blob.
// Usage: go run blob2bin.go <input.go> <output.bin>
package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: blob2bin <input.go> <output.bin>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	re := regexp.MustCompile(`0x([0-9a-fA-F]{2})`)
	matches := re.FindAllSubmatch(data, -1)
	out := make([]byte, 0, len(matches))
	for _, m := range matches {
		v, err := strconv.ParseUint(string(m[1]), 16, 8)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out = append(out, byte(v))
	}
	if err := os.WriteFile(os.Args[2], out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d bytes to %s\n", len(out), os.Args[2])
}