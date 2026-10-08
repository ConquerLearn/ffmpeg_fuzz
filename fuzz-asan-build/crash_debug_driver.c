/* Crash debug driver - prints exception details for UBSan-trap crashes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#ifdef _WIN32
#include <windows.h>
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifdef _WIN32
static jmp_buf __crash_jmp;
static volatile int __crash_occurred = 0;
static volatile EXCEPTION_RECORD __crash_record;

static LONG WINAPI crash_handler(EXCEPTION_POINTERS *ep) {
    __crash_occurred = 1;
    memcpy((void *)&__crash_record, ep->ExceptionRecord, sizeof(EXCEPTION_RECORD));
    longjmp(__crash_jmp, 1);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

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
    
#ifdef _WIN32
    __crash_occurred = 0;
    LPTOP_LEVEL_EXCEPTION_FILTER old_handler = SetUnhandledExceptionFilter(crash_handler);
    if (setjmp(__crash_jmp) == 0) {
        LLVMFuzzerTestOneInput(data, size);
    }
    SetUnhandledExceptionFilter(old_handler);
    if (__crash_occurred) {
        fprintf(stderr, "\n=== CRASH DETAILS ===\n");
        fprintf(stderr, "Exception Code: 0x%08lX\n", __crash_record.ExceptionCode);
        fprintf(stderr, "Exception Address: 0x%p\n", __crash_record.ExceptionAddress);
        
        const char *ex_name = "UNKNOWN";
        switch (__crash_record.ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION: ex_name = "ACCESS_VIOLATION"; break;
            case EXCEPTION_STACK_OVERFLOW: ex_name = "STACK_OVERFLOW"; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION: ex_name = "ILLEGAL_INSTRUCTION (UBSan-trap)"; break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO: ex_name = "INT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_PRIV_INSTRUCTION: ex_name = "PRIV_INSTRUCTION"; break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO: ex_name = "FLT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_FLT_OVERFLOW: ex_name = "FLT_OVERFLOW"; break;
            case EXCEPTION_FLT_UNDERFLOW: ex_name = "FLT_UNDERFLOW"; break;
            case EXCEPTION_FLT_INVALID_OPERATION: ex_name = "FLT_INVALID_OPERATION"; break;
        }
        fprintf(stderr, "Exception Name: %s\n", ex_name);
        
        if (__crash_record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && 
            __crash_record.NumberParameters >= 2) {
            const char *op = "UNKNOWN";
            switch (__crash_record.ExceptionInformation[0]) {
                case 0: op = "READ"; break;
                case 1: op = "WRITE"; break;
                case 8: op = "DEP"; break;
            }
            fprintf(stderr, "Access Operation: %s\n", op);
            fprintf(stderr, "Access Address: 0x%llX\n", 
                    (unsigned long long)__crash_record.ExceptionInformation[1]);
        }
        fprintf(stderr, "====================\n");
    } else {
        fprintf(stderr, "No crash detected\n");
    }
#else
    LLVMFuzzerTestOneInput(data, size);
#endif
    
    free(data);
    return 0;
}