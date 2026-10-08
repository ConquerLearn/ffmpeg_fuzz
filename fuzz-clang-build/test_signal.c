#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>

static jmp_buf g_jmp_buf;
static volatile int abort_caught = 0;

void abort_handler(int sig) {
    (void)sig;
    abort_caught = 1;
    longjmp(g_jmp_buf, 1);
}

int main() {
    printf("Test 1: signal() installation...\n");
    void (*old)(int) = signal(SIGABRT, abort_handler);
    if (old == SIG_ERR) {
        printf("FAIL: signal() returned SIG_ERR\n");
        return 1;
    }
    printf("OK: signal() installed successfully\n");
    
    printf("Test 2: abort() catching...\n");
    if (setjmp(g_jmp_buf) == 0) {
        abort();
    } else {
        printf("OK: abort() caught via longjmp!\n");
    }
    
    signal(SIGABRT, old);
    printf("All tests passed! abort_caught=%d\n", abort_caught);
    return 0;
}