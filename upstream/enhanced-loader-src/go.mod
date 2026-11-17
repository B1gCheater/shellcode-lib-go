// Module boundary for the archived enhancement snapshot. See ../README.md.
//
// This directory holds reference copies of the enhanced loader source and build
// helpers. Nothing here is built or imported by shellcode-lib-go; the nested
// module declaration keeps the parent module from treating the subtree as one of
// its own packages. The live, working copies are under native/rebuild/.
module github.com/B1gCheater/shellcode-lib-go/upstream/enhanced-loader-src

go 1.21