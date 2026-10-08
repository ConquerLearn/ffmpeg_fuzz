/* Minimal test: just link against FFmpeg and exit */
#include <stdio.h>

/* Stub coverage callbacks */
void __sanitizer_cov_trace_pc(void) {}
void __sanitizer_cov_trace_pc_indir(void *callee) { (void)callee; }
void __sanitizer_cov_trace_pc_guard_init(void *start, void *stop) { (void)start; (void)stop; }
void __sanitizer_cov_trace_pc_guard(void *guard) { (void)guard; }

int main(void) {
    fprintf(stderr, "Hello from test_link - FFmpeg libraries loaded successfully!\n");
    return 0;
}