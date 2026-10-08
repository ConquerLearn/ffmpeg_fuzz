#include <stdio.h>
#include <string.h>
int main() {
    FILE *f = fopen("fuzz-corpus/seed_mov_structured.bin", "wb");
    if (!f) { fprintf(stderr, "Cannot open output file\n"); return 1; }
    /* ftyp atom: size=12, type=ftyp, brand=isom */
    unsigned char ftyp[] = {0x00,0x00,0x00,0x0C,'f','t','y','p','i','s','o','m'};
    fwrite(ftyp, 1, sizeof(ftyp), f);
    /* moov atom: size=0x68=104 */
    unsigned char moov_hd[] = {0x00,0x00,0x00,0x68,'m','o','o','v'};
    fwrite(moov_hd, 1, sizeof(moov_hd), f);
    /* mvhd atom: size=0x60=96 */
    unsigned char mvhd_hd[] = {0x00,0x00,0x00,0x60,'m','v','h','d'};
    fwrite(mvhd_hd, 1, sizeof(mvhd_hd), f);
    /* mvhd data: 96 bytes of zeros (version+flags+creation_time+...) */
    unsigned char mvhd_data[96];
    memset(mvhd_data, 0, 96);
    /* Set timescale to 1000 */
    mvhd_data[16] = 0; mvhd_data[17] = 0; mvhd_data[18] = 0x03; mvhd_data[19] = 0xE8;
    fwrite(mvhd_data, 1, sizeof(mvhd_data), f);
    /* mdat atom: size=0x18=24 */
    unsigned char mdat_hd[] = {0x00,0x00,0x00,0x18,'m','d','a','t'};
    fwrite(mdat_hd, 1, sizeof(mdat_hd), f);
    unsigned char mdat_data[16];
    memset(mdat_data, 0xAA, 16); /* fill with non-zero data */
    fwrite(mdat_data, 1, sizeof(mdat_data), f);
    fclose(f);
    printf("Created seed_mov_structured.bin (140 bytes)\n");
    return 0;
}