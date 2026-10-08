#include <stdio.h>
#include <limits.h>

int main(void) {
    /* Test: Signed integer overflow only */
    volatile int x = INT_MAX;
    printf("Before overflow: x=%d\n", x);
    volatile int y = x + 1;  /* UBSan should trap here */
    printf("After overflow: y=%d (should not reach here)\n", y);
    return 0;
}