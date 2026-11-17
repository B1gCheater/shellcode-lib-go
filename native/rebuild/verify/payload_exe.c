// Benign EXE payload: prints a marker and a deterministic computation, then
// returns from main (CRT exit). Used to compare loader behaviour.
#include <stdio.h>

int main(void) {
    volatile int sum = 0;
    for (int i = 1; i <= 100; i++) {
        sum += i;
    }
    printf("PAYLOAD_EXE sum=%d\n", sum);
    fflush(stdout);
    return 0;
}