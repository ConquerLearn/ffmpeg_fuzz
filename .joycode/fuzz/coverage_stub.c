/*
 * Coverage callback stubs for FFmpeg configure/build.
 * Provides __sanitizer_cov_trace_pc() and __sanitizer_cov_trace_pc_indir()
 * so that -fsanitize-coverage=trace-pc instrumented code can link.
 * The real implementations are in standalone_driver.c.
 */

/* Called at each edge by -fsanitize-coverage=trace-pc */
void __sanitizer_cov_trace_pc(void) {
    /* Stub - real implementation in standalone_driver.c */
}

/* Called for indirect calls by -fsanitize-coverage=indirect-calls */
void __sanitizer_cov_trace_pc_indir(void) {
    /* Stub - real implementation in standalone_driver.c */
}

/* Called by -fsanitize-coverage=trace-pc-guard (not used but may be referenced) */
void __sanitizer_cov_trace_pc_guard_init(void *start, void *stop) {
    /* Stub */
}

void __sanitizer_cov_trace_pc_guard(void) {
    /* Stub */
}