/*
 * Standalone Fuzzer Driver for FFmpeg
 * 
 * Supports two coverage instrumentation modes:
 * 1. trace-pc-guard: __sanitizer_cov_trace_pc_guard() callbacks (Linux/ELF)
 * 2. trace-pc: __sanitizer_cov_trace_pc() callbacks (Windows/MinGW/Clang)
 *
 * Usage:
 *   ./fuzzer <input_file>           - Run single input (crash repro)
 *   ./fuzzer --fuzz <dir> <secs>    - Mutation-based fuzzing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <signal.h>

/* The fuzz target entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ===== Coverage Tracking (trace-pc mode) ===== */
/* Uses a simple bitmap to track unique PC values */
#define COVERAGE_MAP_SIZE (1 << 20)  /* 1M entries */
#define COVERAGE_MAP_MASK (COVERAGE_MAP_SIZE - 1)

static uint8_t __coverage_map[COVERAGE_MAP_SIZE];
static volatile int __total_coverage = 0;
static volatile int __run_coverage = 0;

/* Hash a PC value to a bitmap index */
__attribute__((no_sanitize("coverage")))
static inline uint32_t coverage_hash(uintptr_t pc) {
    /* Simple hash: use lower bits after shifting */
    uint32_t idx = (uint32_t)((pc >> 4) ^ (pc >> 16)) & COVERAGE_MAP_MASK;
    return idx;
}

/*
 * Called by -fsanitize-coverage=trace-pc at each edge.
 * CRITICAL: Must have no_sanitize("coverage") to prevent the compiler from
 * inserting trace-pc calls inside this callback, which would cause infinite
 * recursion and stack overflow (STATUS_STACK_OVERFLOW / 0xC00000FD).
 */
__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint32_t idx = coverage_hash(pc);
    if (__coverage_map[idx] == 0) {
        __coverage_map[idx] = 1;
        __total_coverage++;
    }
    __run_coverage = __total_coverage;
}

/* Called by -fsanitize-coverage=trace-pc for indirect calls */
__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_indir(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint32_t idx = coverage_hash(pc);
    if (__coverage_map[idx] == 0) {
        __coverage_map[idx] = 1;
        __total_coverage++;
    }
    __run_coverage = __total_coverage;
}

/* ===== Coverage Tracking (trace-pc-guard mode) ===== */
static uint32_t *__coverage_guard_start = NULL;
static uint32_t *__coverage_guard_stop = NULL;

__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    __coverage_guard_start = start;
    __coverage_guard_stop = stop;
    for (uint32_t *p = start; p < stop; p++) {
        *p = 0;
    }
}

__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (guard && *guard == 0) {
        *guard = 1;
    }
}

/* ===== Crash Detection via SEH (Windows) ===== */
#ifdef _WIN32
#include <windows.h>
static jmp_buf __crash_jmp;
static volatile int __crash_occurred = 0;
static volatile int __abort_occurred = 0;

static LONG WINAPI crash_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        __crash_occurred = 1;
        longjmp(__crash_jmp, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* SIGABRT handler - catches abort() from av_assert0 and similar assertions */
static void abort_handler(int sig) {
    (void)sig;
    __abort_occurred = 1;
    longjmp(__crash_jmp, 1);
}
#endif

/* ===== File I/O ===== */
static uint8_t *read_file(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(*size + 1);
    if (buf) {
        fread(buf, 1, *size, f);
        buf[*size] = 0;
    }
    fclose(f);
    return buf;
}

static void write_crash(const char *dir, int crash_id, const uint8_t *data, size_t size) {
    char path[512];
    snprintf(path, sizeof(path), "%s/crash_%d.bin", dir, crash_id);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, size, f);
        fclose(f);
        fprintf(stderr, "  [CRASH] Saved crash to %s\n", path);
    }
}

/* ===== Mutation Strategies ===== */
static void mutate_flip_bit(uint8_t *data, size_t size) {
    if (size == 0) return;
    size_t pos = rand() % size;
    data[pos] ^= (1 << (rand() % 8));
}

static void mutate_flip_byte(uint8_t *data, size_t size) {
    if (size == 0) return;
    size_t pos = rand() % size;
    data[pos] = rand() % 256;
}

static void mutate_insert_byte(uint8_t *data, size_t *size, size_t max_size) {
    if (*size >= max_size || *size == 0) return;
    size_t pos = rand() % (*size + 1);
    memmove(data + pos + 1, data + pos, *size - pos);
    data[pos] = rand() % 256;
    (*size)++;
}

static void mutate_delete_byte(uint8_t *data, size_t *size) {
    if (*size <= 1) return;
    size_t pos = rand() % *size;
    memmove(data + pos, data + pos + 1, *size - pos - 1);
    (*size)--;
}

static void mutate_splice(uint8_t *data, size_t size, const uint8_t *other, size_t other_size) {
    if (size < 4 || other_size < 4) return;
    size_t pos1 = rand() % (size / 2);
    size_t pos2 = rand() % (other_size / 2);
    size_t avail1 = size - pos1;
    size_t avail2 = other_size - pos2;
    size_t len = rand() % (avail1 < avail2 ? avail1 : avail2) + 1;
    memcpy(data + pos1, other + pos2, len);
}

/* HMN-style interesting values for media format fuzzing */
static void mutate_havoc(uint8_t *data, size_t *size, size_t max_size) {
    /* Apply 2-8 random mutations at once */
    int n = (rand() % 7) + 2;
    for (int i = 0; i < n; i++) {
        int strategy = rand() % 6;
        switch (strategy) {
            case 0: mutate_flip_bit(data, *size); break;
            case 1: mutate_flip_byte(data, *size); break;
            case 2: mutate_insert_byte(data, size, max_size); break;
            case 3: mutate_delete_byte(data, size); break;
            case 4: {
                /* Write interesting byte values */
                if (*size > 0) {
                    static const uint8_t interesting[] = {0, 1, 0xFF, 0x7F, 0x80, 0xFE};
                    size_t pos = rand() % *size;
                    data[pos] = interesting[rand() % (sizeof(interesting)/sizeof(interesting[0]))];
                }
                break;
            }
            case 5: {
                /* Write interesting 16/32-bit values at random positions */
                if (*size >= 4) {
                    size_t pos = rand() % (*size - 3);
                    uint32_t val;
                    switch (rand() % 4) {
                        case 0: val = 0; break;
                        case 1: val = 0xFFFFFFFF; break;
                        case 2: val = rand(); break;
                        case 3: val = 0x01000000; break;
                    }
                    memcpy(data + pos, &val, 4);
                }
                break;
            }
        }
    }
}

/* ===== Coverage Helpers ===== */
static int get_coverage_count(void) {
    /* Prefer trace-pc coverage if available */
    if (__total_coverage > 0) return __total_coverage;
    /* Fall back to trace-pc-guard coverage */
    if (__coverage_guard_start && __coverage_guard_stop) {
        int count = 0;
        for (uint32_t *p = __coverage_guard_start; p < __coverage_guard_stop; p++) {
            if (*p != 0) count++;
        }
        return count;
    }
    return 0;
}

static void reset_run_coverage(void) {
    /* For trace-pc mode, we don't reset (cumulative) */
    /* For trace-pc-guard mode, reset guards */
    if (__coverage_guard_start && __coverage_guard_stop) {
        for (uint32_t *p = __coverage_guard_start; p < __coverage_guard_stop; p++) {
            *p = 0;
        }
    }
}

/* ===== Fuzzing Loop ===== */
static int run_fuzz_loop(const char *corpus_dir, int duration_secs) {
    fprintf(stderr, "=== Coverage-Guided Fuzzing ===\n");
    fprintf(stderr, "Corpus: %s\n", corpus_dir);
    fprintf(stderr, "Duration: %d seconds\n", duration_secs);
    
    /* Load seed corpus */
    #define MAX_INPUTS 10000
    uint8_t *inputs[MAX_INPUTS];
    size_t input_sizes[MAX_INPUTS];
    int num_inputs = 0;
    
    DIR *dir = opendir(corpus_dir);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && num_inputs < MAX_INPUTS) {
            if (ent->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", corpus_dir, ent->d_name);
            size_t sz;
            uint8_t *data = read_file(path, &sz);
            if (data && sz > 0) {
                inputs[num_inputs] = data;
                input_sizes[num_inputs] = sz;
                num_inputs++;
            }
        }
        closedir(dir);
    }
    
    if (num_inputs == 0) {
        uint8_t *seed = (uint8_t *)malloc(64);
        for (int i = 0; i < 64; i++) seed[i] = rand() % 256;
        inputs[0] = seed;
        input_sizes[0] = 64;
        num_inputs = 1;
    }
    
    fprintf(stderr, "Loaded %d seed inputs\n", num_inputs);
    
    #define MAX_MUT_SIZE 131072  /* 128KB max */
    int total_runs = 0;
    int crashes = 0;
    int new_coverage_count = 0;
    int prev_coverage = 0;
    time_t start_time = time(NULL);
    time_t last_report = start_time;
    
    while (difftime(time(NULL), start_time) < duration_secs) {
        /* Pick a random input as base */
        int idx = rand() % num_inputs;
        size_t mut_size = input_sizes[idx];
        uint8_t *mut_data = (uint8_t *)malloc(MAX_MUT_SIZE);
        if (!mut_data) break;
        memcpy(mut_data, inputs[idx], mut_size);
        
        /* Apply mutations - use havoc mode 30% of the time */
        if (rand() % 10 < 3) {
            mutate_havoc(mut_data, &mut_size, MAX_MUT_SIZE);
        } else {
            int num_mutations = (rand() % 5) + 1;
            for (int m = 0; m < num_mutations; m++) {
                int strategy = rand() % 5;
                switch (strategy) {
                    case 0: mutate_flip_bit(mut_data, mut_size); break;
                    case 1: mutate_flip_byte(mut_data, mut_size); break;
                    case 2: mutate_insert_byte(mut_data, &mut_size, MAX_MUT_SIZE); break;
                    case 3: mutate_delete_byte(mut_data, &mut_size); break;
                    case 4:
                        if (num_inputs > 1) {
                            int other = rand() % num_inputs;
                            if (other != idx) {
                                mutate_splice(mut_data, mut_size, inputs[other], input_sizes[other]);
                            }
                        }
                        break;
                }
            }
        }
        
        /* Run the fuzz target with crash detection */
        int cov_before = get_coverage_count();
        
#ifdef _WIN32
        __crash_occurred = 0;
        __abort_occurred = 0;
        LPTOP_LEVEL_EXCEPTION_FILTER old_handler = SetUnhandledExceptionFilter(crash_handler);
        void (*old_sigabrt)(int) = signal(SIGABRT, abort_handler);
        if (setjmp(__crash_jmp) == 0) {
            LLVMFuzzerTestOneInput(mut_data, mut_size);
        }
        SetUnhandledExceptionFilter(old_handler);
        signal(SIGABRT, old_sigabrt);
        if (__crash_occurred || __abort_occurred) {
            crashes++;
            write_crash(corpus_dir, crashes, mut_data, mut_size);
            if (__abort_occurred) {
                fprintf(stderr, "  [ASSERT] abort()/av_assert0 caught at run #%d\n", total_runs + 1);
            }
            free(mut_data);
            total_runs++;
            continue;
        }
#else
        LLVMFuzzerTestOneInput(mut_data, mut_size);
#endif
        
        /* Check coverage */
        int cov_after = get_coverage_count();
        if (cov_after > cov_before) {
            /* New coverage found - keep this input */
            if (num_inputs < MAX_INPUTS) {
                inputs[num_inputs] = mut_data;
                input_sizes[num_inputs] = mut_size;
                num_inputs++;
                new_coverage_count++;
            } else {
                free(mut_data);
            }
            prev_coverage = cov_after;
        } else {
            free(mut_data);
        }
        
        total_runs++;
        
        /* Report progress every 10 seconds */
        time_t now = time(NULL);
        if (difftime(now, last_report) >= 10) {
            fprintf(stderr, "  [%d/%ds] runs=%d corpus=%d coverage=%d crashes=%d\n",
                    (int)difftime(now, start_time), duration_secs,
                    total_runs, num_inputs, prev_coverage, crashes);
            last_report = now;
        }
    }
    
    fprintf(stderr, "\n=== Fuzzing Complete ===\n");
    fprintf(stderr, "Total runs: %d\n", total_runs);
    fprintf(stderr, "Final corpus: %d inputs\n", num_inputs);
    fprintf(stderr, "Coverage edges: %d\n", prev_coverage);
    fprintf(stderr, "New coverage found: %d times\n", new_coverage_count);
    fprintf(stderr, "Crashes: %d\n", crashes);
    
    /* Cleanup */
    for (int i = 0; i < num_inputs; i++) {
        free(inputs[i]);
    }
    
    return crashes;
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL) ^ (unsigned int)clock());
    
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <input_file>           - Run single input (crash repro)\n", argv[0]);
        fprintf(stderr, "  %s --fuzz <dir> <secs>    - Coverage-guided fuzzing\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "--fuzz") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s --fuzz <corpus_dir> <duration_secs>\n", argv[0]);
            return 1;
        }
        const char *corpus_dir = argv[2];
        int duration = atoi(argv[3]);
        if (duration <= 0) duration = 60;
        return run_fuzz_loop(corpus_dir, duration);
    }
    
    /* Single file mode */
    size_t size;
    uint8_t *data = read_file(argv[1], &size);
    if (!data) {
        fprintf(stderr, "Error: cannot read %s\n", argv[1]);
        return 1;
    }
    
    fprintf(stderr, "Running %s (%zu bytes)...\n", argv[1], size);
    
#ifdef _WIN32
    __crash_occurred = 0;
    __abort_occurred = 0;
    LPTOP_LEVEL_EXCEPTION_FILTER old_handler = SetUnhandledExceptionFilter(crash_handler);
    void (*old_sigabrt)(int) = signal(SIGABRT, abort_handler);
    if (setjmp(__crash_jmp) == 0) {
        LLVMFuzzerTestOneInput(data, size);
    }
    SetUnhandledExceptionFilter(old_handler);
    signal(SIGABRT, old_sigabrt);
    if (__crash_occurred) {
        fprintf(stderr, "CRASH detected!\n");
    }
    if (__abort_occurred) {
        fprintf(stderr, "ASSERTION failure (abort/av_assert0) detected!\n");
    }
#else
    LLVMFuzzerTestOneInput(data, size);
#endif
    
    fprintf(stderr, "Done. Coverage: %d edges\n", get_coverage_count());
    
    free(data);
    return 0;
}