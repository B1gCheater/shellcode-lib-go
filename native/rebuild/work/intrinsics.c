// Build shim for -nostdlib loader builds with modern GCC.
//
// GCC lowers large struct copies / zeroing to implicit calls to memcpy/memset
// even at -O0. donut ships Memcpy/Memset (capitalised) and, for MSVC, maps memcmp
// to Memcmp, but the lowercase intrinsics GCC emits are left undefined under
// -nostdlib. Provide them here as byte loops.
//
// -fno-builtin (passed on the command line) stops GCC from recognising these
// bodies as the standard functions and rewriting them into a recursive call to
// themselves. This file is a build artefact of the isolated rebuild workspace; it
// is not part of the upstream source or the archived enhancement patch.

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) { *d++ = *s++; }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) { *d++ = (unsigned char)c; }
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--) { *d++ = *s++; }
    } else {
        d += n; s += n;
        while (n--) { *--d = *--s; }
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y) { return *x < *y ? -1 : 1; }
        x++; y++;
    }
    return 0;
}