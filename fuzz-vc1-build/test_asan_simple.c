// 简单ASAN测试
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("ASAN test starting...\n");
    
    // 堆缓冲区溢出测试
    char *buf = (char*)malloc(10);
    memset(buf, 0, 10);
    printf("Writing beyond buffer...\n");
    buf[10] = 'X';  // 堆溢出
    printf("After write (should not reach here with ASAN)\n");
    
    free(buf);
    return 0;
}