/* Minimal driver for ASAN crash reproduction - no signal handlers */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = (uint8_t *)malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    fprintf(stderr, "Running %s (%zu bytes)...\n", argv[1], size);
    int ret = LLVMFuzzerTestOneInput(data, size);
    fprintf(stderr, "Returned: %d\n", ret);
    free(data);
    return 0;
}