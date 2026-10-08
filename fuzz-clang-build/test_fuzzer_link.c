/* Test: link with standalone_driver.o coverage callbacks + FFmpeg */
#include <stdio.h>
#include <stdint.h>

/* The real coverage callbacks are in standalone_driver.o */
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "test_fuzzer_link: starting...\n");
    
    /* Try a minimal H.264 input */
    uint8_t data[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x0a};
    size_t size = sizeof(data);
    
    fprintf(stderr, "test_fuzzer_link: calling LLVMFuzzerTestOneInput...\n");
    int ret = LLVMFuzzerTestOneInput(data, size);
    fprintf(stderr, "test_fuzzer_link: done, ret=%d\n", ret);
    
    return 0;
}