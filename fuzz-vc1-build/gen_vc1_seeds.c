/* Generate multiple VC-1 fuzzer seeds with different profiles/sizes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const uint64_t FUZZ_TAG = 0x4741542D5A5A5546ULL;

static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val); buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16); buf[3] = (uint8_t)(val >> 24);
}
static void write_le64(uint8_t *buf, uint64_t val) {
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(val >> (i * 8));
}

static int write_seed(const char *outfile, int width, int height,
                       uint8_t *seq_hdr, int seq_hdr_len,
                       uint8_t *ep_data, int ep_len,
                       uint8_t *frame_data, int frame_len) {
    uint8_t packet[2048];
    int pos = 0;
    
    /* Sequence Header */
    memcpy(packet + pos, seq_hdr, seq_hdr_len);
    pos += seq_hdr_len;
    
    /* Entry Point */
    if (ep_data && ep_len > 0) {
        uint8_t ep_start[] = {0x00, 0x00, 0x01, 0x0D};
        memcpy(packet + pos, ep_start, 4); pos += 4;
        memcpy(packet + pos, ep_data, ep_len);
        pos += ep_len;
    }
    
    /* Frame with FUZZ_TAG */
    uint8_t frame_start[] = {0x00, 0x00, 0x01, 0x0C};
    memcpy(packet + pos, frame_start, 4); pos += 4;
    if (frame_data && frame_len > 0) {
        memcpy(packet + pos, frame_data, frame_len);
        pos += frame_len;
    }
    
    /* FUZZ_TAG */
    memcpy(packet + pos, &FUZZ_TAG, 8); pos += 8;
    
    /* Second frame */
    memcpy(packet + pos, frame_start, 4); pos += 4;
    if (frame_data && frame_len > 0) {
        memcpy(packet + pos, frame_data, frame_len > 32 ? 32 : frame_len);
        pos += (frame_len > 32 ? 32 : frame_len);
    }
    
    int packet_size = pos;
    
    /* Configuration area (1024 bytes) */
    uint8_t config[1024];
    memset(config, 0, sizeof(config));
    int c = 0;
    write_le32(config + c, width); c += 4;
    write_le32(config + c, height); c += 4;
    write_le64(config + c, 0); c += 8;  /* bit_rate */
    write_le32(config + c, 0); c += 4;  /* bits_per_coded_sample */
    config[c++] = 0x01;  /* flags: enable parser */
    write_le32(config + c, 0); c += 4;  /* extradata_size */
    write_le32(config + c, 0); c += 4;  /* sample_rate */
    write_le32(config + c, 0); c += 4;  /* channels */
    write_le32(config + c, 0); c += 4;  /* block_align */
    write_le32(config + c, 0); c += 4;  /* codec_tag */
    write_le64(config + c, 0); c += 8;  /* keyframes */
    write_le64(config + c, 0); c += 8;  /* request_channel_layout */
    config[c++] = 0;  /* idct_algo */
    write_le64(config + c, 0); c += 8;  /* flushpattern */
    config[c++] = 0;  /* skip_frame */
    
    FILE *f = fopen(outfile, "wb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", outfile); return -1; }
    fwrite(packet, 1, packet_size, f);
    fwrite(config, 1, sizeof(config), f);
    fclose(f);
    printf("  Written: %s (%d bytes)\n", outfile, packet_size + 1024);
    return 0;
}

int main(int argc, char **argv) {
    const char *basedir = argc > 1 ? argv[1] : "c:\\Users\\Administrator\\Desktop\\1\\8-6\\FFmpeg-release-8.1\\fuzz-corpus";
    char path[512];
    
    srand(42);
    
    printf("Generating VC-1 fuzzer seeds...\n");
    
    /* Seed 1: Advanced Profile 320x240 */
    {
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x20, 0x00,0x00, 0x01,0x30,0x0E,
                         /* more header bytes for advanced profile */
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t ep[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[64];
        for (int i = 0; i < 64; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_adv_320.bin", basedir);
        write_seed(path, 320, 240, seq, sizeof(seq), ep, sizeof(ep), frame, 64);
    }
    
    /* Seed 2: Advanced Profile 640x480 */
    {
        /* max_coded_width = 640/16-1 = 39, max_coded_height = 480/16-1 = 29 */
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x20, 0x00,0x00, 0x02,0x70,0x1D,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t ep[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[128];
        for (int i = 0; i < 128; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_adv_640.bin", basedir);
        write_seed(path, 640, 480, seq, sizeof(seq), ep, sizeof(ep), frame, 128);
    }
    
    /* Seed 3: Advanced Profile 192x128 (small) */
    {
        /* max_coded_width = 192/16-1 = 11, max_coded_height = 128/16-1 = 7 */
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x20, 0x00,0x00, 0x00,0xB0,0x07,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t ep[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[32];
        for (int i = 0; i < 32; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_adv_192.bin", basedir);
        write_seed(path, 192, 128, seq, sizeof(seq), ep, sizeof(ep), frame, 32);
    }
    
    /* Seed 4: Simple/Main Profile (start code 0x0000010F, profile=0 or 1) */
    {
        /* Simple profile: profile bits = 00, then structure info */
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x80, 0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[64];
        for (int i = 0; i < 64; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_simple.bin", basedir);
        write_seed(path, 320, 240, seq, sizeof(seq), NULL, 0, frame, 64);
    }
    
    /* Seed 5: Main Profile */
    {
        /* Main profile: profile bits = 01 */
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x40, 0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[64];
        for (int i = 0; i < 64; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_main.bin", basedir);
        write_seed(path, 320, 240, seq, sizeof(seq), NULL, 0, frame, 64);
    }
    
    /* Seed 6: Large Advanced Profile 1280x720 (stress test) */
    {
        /* max_coded_width = 1280/16-1 = 79, max_coded_height = 720/16-1 = 44 */
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x20, 0x00,0x00, 0x04,0xF0,0x2C,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t ep[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        uint8_t frame[256];
        for (int i = 0; i < 256; i++) frame[i] = (uint8_t)(rand() % 256);
        snprintf(path, sizeof(path), "%s\\seed_vc1_adv_1280.bin", basedir);
        write_seed(path, 1280, 720, seq, sizeof(seq), ep, sizeof(ep), frame, 256);
    }
    
    /* Seed 7: Minimal - just start codes and config */
    {
        uint8_t seq[] = {0x00,0x00,0x01,0x0F, 0x20};
        uint8_t frame[8] = {0x00,0x00,0x01,0x0C, 0x00,0x00,0x00,0x00};
        snprintf(path, sizeof(path), "%s\\seed_vc1_minimal.bin", basedir);
        write_seed(path, 64, 64, seq, sizeof(seq), NULL, 0, frame, 8);
    }
    
    printf("Done. 7 seeds generated.\n");
    return 0;
}