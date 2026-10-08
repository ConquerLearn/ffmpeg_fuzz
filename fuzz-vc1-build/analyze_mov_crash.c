// MOV crash分析工具
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    const char *path = "../fuzz-corpus-mov/crash_1.bin";
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", path); return 1; }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    printf("File size: %ld bytes\n", size);
    printf("MOV data: %ld bytes (size - 2048)\n", size - 2048);
    
    if (size < 2048) {
        printf("ERROR: File too small for IO_FLAT=0 config\n");
        free(data);
        return 1;
    }
    
    // Config区 (倒数2048-1024字节)
    uint8_t *config = data + size - 2048;
    uint32_t io_buf_size = *(uint32_t*)(config + 0);
    uint8_t flags = config[4];
    uint64_t filesize = *(uint64_t*)(config + 12);
    uint32_t interrupt_ctr = *(uint32_t*)(config + 20);
    
    printf("\nConfig:\n");
    printf("  io_buffer_size: %u\n", io_buf_size);
    printf("  flags: 0x%02x (seekable=%d)\n", flags, flags & 1);
    printf("  filesize: %llu\n", (unsigned long long)filesize);
    printf("  interrupt_counter: %u\n", interrupt_ctr);
    
    // Filename区 (最后1024字节)
    uint8_t *filename = data + size - 1024;
    printf("  filename: \"%s\"\n", filename);
    
    // MOV数据
    long mov_size = size - 2048;
    uint8_t *mov = data;
    
    printf("\nMOV data first 128 bytes:\n");
    for (int i = 0; i < 128 && i < mov_size; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16 && i+j < mov_size; j++)
            printf("%02x ", mov[i+j]);
        printf(" ");
        for (int j = 0; j < 16 && i+j < mov_size; j++)
            printf("%c", (mov[i+j] >= 32 && mov[i+j] < 127) ? mov[i+j] : '.');
        printf("\n");
    }
    
    // Atom结构
    printf("\nAtom structure:\n");
    long pos = 0;
    int atom_count = 0;
    while (pos < mov_size - 8 && atom_count < 20) {
        uint32_t atom_size = (mov[pos] << 24) | (mov[pos+1] << 16) | (mov[pos+2] << 8) | mov[pos+3];
        char atom_type[5] = {mov[pos+4], mov[pos+5], mov[pos+6], mov[pos+7], 0};
        printf("  Atom at %ld: type='%s' size=%u\n", pos, atom_type, atom_size);
        if (atom_size < 8 || pos + atom_size > mov_size) {
            printf("    [INVALID: truncated or corrupt]\n");
            break;
        }
        pos += atom_size;
        atom_count++;
    }
    
    free(data);
    return 0;
}