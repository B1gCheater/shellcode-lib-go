module github.com/B1gCheater/shellcode-lib-go

go 1.21

// No third-party dependencies. The library is pure Go and cross-compiles to
// any target, because the shellcode it produces contains no host-specific
// layout: the instance is assembled into a byte slice at fixed offsets.
