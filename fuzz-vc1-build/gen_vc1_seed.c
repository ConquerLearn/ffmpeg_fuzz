/* Generate VC-1 fuzzer seed with Advanced profile header */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* FUZZ_TAG from target_dec_fuzzer.c */
static const uint64_t FUZZ_TAG = 0x4741542D5A5A5546ULL;

static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

static void write_le64(uint8_t *buf, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)(val >> (i * 8));
}

int main(int argc, char **argv) {
    const char *outfile = argc > 1 ? argv[1] : "fuzz-corpus/seed_vc1_adv.bin";
    
    /* VC-1 Advanced Profile Sequence Header
     * Start code: 00 00 01 0F
     * Profile: Advanced (bits: 10 = 0x20)
     * Then sequence header fields...
     */
    
    uint8_t packet[512];
    int pos = 0;
    
    /* Sequence Header start code */
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x01; packet[pos++] = 0x0F;
    
    /* Profile: Advanced = 2 (2 bits: 10) */
    /* After start code, the sequence header for Advanced profile:
     * - profile (2 bits): 10 = Advanced
     * - seq_layer_structure (varies)
     * We'll use a minimal valid Advanced profile header
     */
    /* Advanced profile marker: first byte after start code 
     * Bits: [10][xxxxxx] where 10 = Advanced profile
     * 0x20 = 0010 0000 -> profile=10 (Advanced), then zeros
     */
    packet[pos++] = 0x20;  /* Advanced profile */
    
    /* Advanced profile sequence header fields (simplified):
     * - interlace (1 bit): 0
     * - tfcntr (1 bit): 0  
     * - finterpflag (1 bit): 0
     * - psf (1 bit): 0
     * - multires (1 bit): 0
     * - reserved (1 bit): 0
     * - max_b_frames (3 bits): 0
     * - quantizer (2 bits): 0
     * - extended_dmv (1 bit): 0
     * - dquant (1 bit): 0
     * - vopdquant (1 bit): 0
     * - overlap (1 bit): 0
     * - syncmarker (1 bit): 0
     * - rangered (1 bit): 0
     * - max_coded_width (12 bits): e.g. 320/16-1=19
     * - max_coded_height (12 bits): e.g. 240/16-1=14
     * ... lots more bits
     */
    /* Simplified: just put some bytes that might parse */
    packet[pos++] = 0x00;  /* interlace=0, tfcntr=0, finterpflag=0, psf=0, multires=0, res=0, max_b=00 */
    packet[pos++] = 0x00;  /* max_b_frames cont=0, quantizer=00, extended_dmv=0, dquant=0, vopdquant=0, overlap=0, syncmarker=0, rangered=0 */
    /* max_coded_width=19 (12 bits): 0000 0001 0011 */
    /* max_coded_height=14 (12 bits): 0000 0000 1110 */
    packet[pos++] = 0x01;  /* width high bits: 0000 0001 */
    packet[pos++] = 0x30;  /* width low 4 bits: 0011, height high 8 bits: 0000 0000 */
    packet[pos++] = 0x0E;  /* height low bits: 1110 */
    
    /* Fill remaining with zeros/padding */
    for (int i = pos; i < 64; i++) {
        packet[pos++] = 0x00;
    }
    
    /* Entry Point start code */
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x01; packet[pos++] = 0x0D;
    /* Entry point data (simplified) */
    for (int i = 0; i < 32; i++) {
        packet[pos++] = 0x00;
    }
    
    /* Frame start code */
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x01; packet[pos++] = 0x0C;
    /* Frame data */
    for (int i = 0; i < 128; i++) {
        packet[pos++] = (uint8_t)(rand() % 256);
    }
    
    /* Add FUZZ_TAG separator */
    memcpy(packet + pos, &FUZZ_TAG, 8);
    pos += 8;
    
    /* Second frame */
    packet[pos++] = 0x00; packet[pos++] = 0x00; packet[pos++] = 0x01; packet[pos++] = 0x0C;
    for (int i = 0; i < 64; i++) {
        packet[pos++] = (uint8_t)(rand() % 256);
    }
    
    int packet_size = pos;
    
    /* Configuration area (1024 bytes) */
    uint8_t config[1024];
    memset(config, 0, sizeof(config));
    int coffset = 0;
    
    /* width = 320 */
    write_le32(config + coffset, 320); coffset += 4;
    /* height = 240 */
    write_le32(config + coffset, 240); coffset += 4;
    /* bit_rate = 0 */
    write_le64(config + coffset, 0); coffset += 8;
    /* bits_per_coded_sample = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* flags = 0x01 (enable parser) */
    config[coffset++] = 0x01;
    /* extradata_size = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* sample_rate = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* channels = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* block_align = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* codec_tag = 0 */
    write_le32(config + coffset, 0); coffset += 4;
    /* keyframes = 0 */
    write_le64(config + coffset, 0); coffset += 8;
    /* request_channel_layout = 0 */
    write_le64(config + coffset, 0); coffset += 8;
    /* idct_algo = 0 */
    config[coffset++] = 0;
    /* flushpattern = 0 */
    write_le64(config + coffset, 0); coffset += 8;
    /* skip_frame = 0 */
    config[coffset++] = 0;
    
    /* Write output */
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        fprintf(stderr, "Cannot open %s for writing\n", outfile);
        return 1;
    }
    fwrite(packet, 1, packet_size, f);
    fwrite(config, 1, sizeof(config), f);
    fclose(f);
    
    printf("VC-1 seed written: %d bytes (packet=%d + config=1024)\n", 
           packet_size + 1024, packet_size);
    printf("  Output: %s\n", outfile);
    printf("  Profile: Advanced\n");
    printf("  Config: width=320, height=240\n");
    
    return 0;
}