// Coverage callback provider for trace-pc mode
#include <stdint.h>
#include <stddef.h>

// trace-pc mode callbacks
void __sanitizer_cov_trace_pc(void) {}
void __sanitizer_cov_trace_pc_indirect(void) {}

int main(void) {
    return 0;
}