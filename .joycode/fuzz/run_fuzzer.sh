#!/bin/bash
# FFmpeg libFuzzer Run Script
# Runs fuzz targets with configurable duration and options
# Usage: bash run_fuzzer.sh [--target TARGET] [--duration SECONDS] [--corpus DIR]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$FFMPEG_ROOT/fuzz-build"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"
CRASH_DIR="$FFMPEG_ROOT/fuzz-crashes"
COVERAGE_DIR="$FFMPEG_ROOT/fuzz-coverage"

# Default settings
DURATION=3600       # 1 hour default
MAX_LEN=100000      # Max input length
TARGET="all"        # Run all targets
JOBS=0              # 0 = auto-detect (parallel fuzzing)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target) TARGET="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --corpus) CORPUS_DIR="$2"; shift 2 ;;
        --max-len) MAX_LEN="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "========================================"
echo "  FFmpeg libFuzzer Fuzzing Session"
echo "========================================"
echo "Target:    $TARGET"
echo "Duration:  ${DURATION}s ($(($DURATION / 3600))h $(($DURATION % 3600 / 60))m)"
echo "Max len:   $MAX_LEN"
echo "Corpus:    $CORPUS_DIR"
echo "Crashes:   $CRASH_DIR"
echo ""

# Create directories
mkdir -p "$CORPUS_DIR" "$CRASH_DIR" "$COVERAGE_DIR"

# Define available targets
declare -A TARGETS
TARGETS["dec_h264"]="target_dec_h264_fuzzer"
TARGETS["dem_mov"]="target_dem_mov_fuzzer"
TARGETS["bsf"]="target_bsf_fuzzer"

# Generate minimal seed corpus if empty
if [[ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]]; then
    echo "=== Generating seed corpus ==="
    # Create minimal valid inputs for each target type
    # Minimal H.264 NAL unit (SPS)
    printf '\x00\x00\x00\x01\x67\x42\x00\x0a\xf8\x41\xa2' > "$CORPUS_DIR/seed_h264_min.bin"
    # Minimal MOV container (ftyp box)
    printf '\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x00\x00\x69\x73\x6f\x6d' > "$CORPUS_DIR/seed_mov_min.bin"
    # Random small seed
    dd if=/dev/urandom of="$CORPUS_DIR/seed_random_1.bin" bs=256 count=1 2>/dev/null
    dd if=/dev/urandom of="$CORPUS_DIR/seed_random_2.bin" bs=1024 count=1 2>/dev/null
    dd if=/dev/urandom of="$CORPUS_DIR/seed_random_3.bin" bs=4096 count=1 2>/dev/null
    echo "Seed corpus created with initial inputs"
fi

# Run fuzzing
run_target() {
    local TARGET_NAME=$1
    local TARGET_BIN=$2
    local TARGET_CORPUS="$CORPUS_DIR/$TARGET_NAME"
    local TARGET_CRASH="$CRASH_DIR/$TARGET_NAME"

    mkdir -p "$TARGET_CORPUS" "$TARGET_CRASH"

    if [[ ! -f "$BUILD_DIR/$TARGET_BIN" ]]; then
        echo "SKIP: $TARGET_BIN not found. Run build_ffmpeg_fuzzer.sh first."
        return 1
    fi

    echo "----------------------------------------"
    echo "Fuzzing: $TARGET_NAME ($TARGET_BIN)"
    echo "Start:   $(date)"
    echo ""

    # Copy seeds to target corpus
    cp "$CORPUS_DIR"/seed_*.bin "$TARGET_CORPUS/" 2>/dev/null || true

    # Run libFuzzer
    "$BUILD_DIR/$TARGET_BIN" \
        -max_len="$MAX_LEN" \
        -max_total_time="$DURATION" \
        -artifact_prefix="$TARGET_CRASH/" \
        -jobs="$JOBS" \
        "$TARGET_CORPUS" \
        2>&1 | tee "$CRASH_DIR/${TARGET_NAME}_fuzz.log" || true

    echo ""
    echo "Finished: $TARGET_NAME at $(date)"

    # Check for crashes
    local CRASH_COUNT=$(ls -1 "$TARGET_CRASH"/*.crash 2>/dev/null | wc -l || echo "0")
    if [[ $CRASH_COUNT -gt 0 ]]; then
        echo "!!! CRASHES FOUND: $CRASH_COUNT in $TARGET_NAME !!!"
        echo "Crash files in: $TARGET_CRASH/"
    fi
}

# Select targets to run
if [[ "$TARGET" == "all" ]]; then
    for T in "${!TARGETS[@]}"; do
        run_target "$T" "${TARGETS[$T]}"
    done
elif [[ -n "${TARGETS[$TARGET]}" ]]; then
    run_target "$TARGET" "${TARGETS[$TARGET]}"
else
    echo "Unknown target: $TARGET"
    echo "Available targets: all ${!TARGETS[@]}"
    exit 1
fi

echo ""
echo "========================================"
echo "  Fuzzing Session Complete"
echo "========================================"
echo "Check crash reports in: $CRASH_DIR/"
echo ""

# List all crashes
echo "=== Crash Summary ==="
find "$CRASH_DIR" -name "*.crash" -o -name "crash-*" 2>/dev/null | while read -r f; do
    echo "  $f"
done || echo "No crashes found"

echo ""
echo "To reproduce a crash:"
echo "  \$BUILD_DIR/<fuzzer_binary> <crash_file>"