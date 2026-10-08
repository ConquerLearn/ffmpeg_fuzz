#include <stdio.h>

// Minimal test - just call one FFmpeg function
extern const char* av_version_info(void);
extern unsigned avutil_version(void);

int main() {
    printf("av_version_info: %s\n", av_version_info());
    printf("avutil_version: %u\n", avutil_version());
    return 0;
}