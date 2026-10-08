#include <stdio.h>

// Test with more FFmpeg functions
extern const char* av_version_info(void);
extern unsigned avutil_version(void);
extern unsigned avcodec_version(void);
extern unsigned avformat_version(void);
extern unsigned swscale_version(void);
extern unsigned swresample_version(void);

int main() {
    printf("av_version_info: %s\n", av_version_info());
    printf("avutil_version: %u\n", avutil_version());
    printf("avcodec_version: %u\n", avcodec_version());
    printf("avformat_version: %u\n", avformat_version());
    printf("swscale_version: %u\n", swscale_version());
    printf("swresample_version: %u\n", swresample_version());
    return 0;
}