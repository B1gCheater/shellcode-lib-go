// This module declaration exists only to exclude the archived upstream sources
// from the parent module's build.
//
// The archive contains donut's own generated loader arrays (loader_exe_x86.go,
// loader_exe_x64.go), which declare `package donut`. Without a nested go.mod the
// Go tool would treat this directory as a package of the parent module, compile
// it, and ship it to consumers. A nested module boundary makes the parent ignore
// this subtree entirely, so the archive stays inert reference material.
//
// Nothing here is built, imported, or tested by shellcode-lib-go. Do not add this
// module to the parent's require list.
module github.com/B1gCheater/shellcode-lib-go/upstream/donut-1.02

go 1.21