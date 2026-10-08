#include <stdio.h>
#include <stdint.h>

/* Coverage callback - minimal implementation */
void __sanitizer_cov_trace_pc(void) {
    /* Just count, no memory allocation */
    static int count = 0;
    count++;
}

void __sanitizer_cov_trace_pc_indir(void *callee) {
    (void)callee;
}

int main(void) {
    printf("Hello from trace-pc test! count=%d\n", 0);
    return 0;
}