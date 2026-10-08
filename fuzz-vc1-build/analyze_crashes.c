/* Analyze H.264 crash samples - extract config area parameters */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t read_le32(const uint8_t *p) {
    return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}
static uint64_t read_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i*8);
    return v;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: analyze_crashes <crash_files...>\n");
        return 1;
    }
    
    printf("%-15s %6s %6s %8s %6s %6s %6s %6s\n", 
           "File", "Size", "Width", "Height", "Flags", "ExtrSz", "PktLen", "PktCnt");
    printf("--------------- ------ ------ -------- ------ ------ ------ ------\n");
    
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { fprintf(stderr, "Cannot open %s\n", argv[i]); continue; }
        
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        uint8_t *data = malloc(size);
        fread(data, 1, size, f);
        fclose(f);
        
        if (size < 1024) {
            printf("%-15s %6ld (too small, no config)\n", argv[i], size);
            free(data);
            continue;
        }
        
        /* Config area is last 1024 bytes for decoder fuzzer */
        const uint8_t *config = data + size - 1024;
        uint32_t width = read_le32(config);
        uint32_t height = read_le32(config + 4);
        uint64_t bit_rate = read_le64(config + 8);
        uint32_t bits_per_coded = read_le32(config + 16);
        uint8_t flags = config[20];
        uint32_t extradata_size = read_le32(config + 21);
        uint32_t sample_rate = read_le32(config + 25);
        uint32_t channels = read_le32(config + 29);
        uint32_t block_align = read_le32(config + 33);
        uint32_t codec_tag = read_le32(config + 37);
        
        /* Count FUZZ_TAG occurrences in packet data */
        const uint8_t FUZZ_TAG[] = {0x46, 0x55, 0x5A, 0x5A, 0x2D, 0x54, 0x41, 0x47};
        int pkt_count = 0;
        int pkt_len = size - 1024; /* total packet data length */
        for (int j = 0; j < pkt_len - 8; j++) {
            if (memcmp(data + j, FUZZ_TAG, 8) == 0) pkt_count++;
        }
        
        /* Extract just filename */
        const char *fname = strrchr(argv[i], '\\');
        fname = fname ? fname + 1 : argv[i];
        
        printf("%-15s %6ld %6u %8u 0x%02x   %5u %6d %6d\n",
               fname, size, width, height, flags, extradata_size, pkt_len, pkt_count);
        
        free(data);
    }
    return 0;
}