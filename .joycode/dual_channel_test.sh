#!/bin/bash
# FFmpeg Dual-Channel Security Testing Framework
# Combines CodeQL Static Analysis + libFuzzer Dynamic Fuzzing
# Usage: bash dual_channel_test.sh [--channel codeql|fuzzer|both] [--duration SECONDS]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$FFMPEG_ROOT/.joycode/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default settings
CHANNEL="both"
DURATION=600       # 10 minutes default for fuzzing
CODEQL_MODE="quick" # quick = taint tracking only, full = all queries

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --channel) CHANNEL="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --codeql-mode) CODEQL_MODE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  FFmpeg Dual-Channel Security Testing${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "  Channel:   $CHANNEL"
echo -e "  Duration:  ${DURATION}s (fuzzing)"
echo -e "  CodeQL:    $CODEQL_MODE mode"
echo -e "  Report:    $REPORT_DIR/dual_report_${TIMESTAMP}.txt"
echo ""

mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/dual_report_${TIMESTAMP}.txt"

# Initialize report
cat > "$REPORT_FILE" << EOF
========================================
  FFmpeg Dual-Channel Security Test Report
  Generated: $(date)
  Channel: $CHANNEL
  Fuzzing Duration: ${DURATION}s
  CodeQL Mode: $CODEQL_MODE
========================================

EOF

echo "========================================" | tee -a "$REPORT_FILE"
echo "  FFmpeg Dual-Channel Security Test" | tee -a "$REPORT_FILE"
echo "  Started: $(date)" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# ========================================
# CHANNEL 1: CodeQL Static Analysis
# ========================================
run_codeql() {
    echo -e "${YELLOW}>>> Channel 1: CodeQL Static Analysis${NC}"
    echo "" | tee -a "$REPORT_FILE"
    echo "=== CHANNEL 1: CODEQL STATIC ANALYSIS ===" | tee -a "$REPORT_FILE"
    echo "Start: $(date)" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    CODEQL_BIN="$FFMPEG_ROOT/.tools/codeql/codeql.exe"
    CODEQL_DB="$FFMPEG_ROOT/.codeql-db/cpp"
    QUERIES_DIR="$SCRIPT_DIR/queries"

    if [[ ! -d "$CODEQL_DB" ]]; then
        echo "ERROR: CodeQL database not found" | tee -a "$REPORT_FILE"
        return 1
    fi

    # Define queries based on mode
    if [[ "$CODEQL_MODE" == "quick" ]]; then
        QUERIES=("TaintedAllocSize" "TaintedMemcpySize" "TaintedArrayIndex")
    else
        QUERIES=("AvFreeUseAfterFreeV2" "ResourceLeakErrorPathV2" "AVPacketLeak" "AVBufferRefImbalance" "TaintedAllocSize" "TaintedMemcpySize" "TaintedArrayIndex")
    fi

    TOTAL_CODEQL=0
    HIGH_SEVERITY=0

    for Q in "${QUERIES[@]}"; do
        QL_FILE="$QUERIES_DIR/${Q}.ql"
        if [[ ! -f "$QL_FILE" ]]; then
            echo "SKIP: $Q (file not found)" | tee -a "$REPORT_FILE"
            continue
        fi

        echo -n "  Running $Q... " | tee -a "$REPORT_FILE"
        START=$(date +%s)

        RESULT=$("$CODEQL_BIN" database analyze "$CODEQL_DB" "$QL_FILE" \
            --output="$REPORT_DIR/${Q}.bqrs" --rerun 2>&1 | tail -1 || echo "ERROR")

        END=$(date +%s)
        DURATION_Q=$((END - START))

        # Count results
        COUNT=$("$CODEQL_BIN" bqrs decode --format=csv "$REPORT_DIR/${Q}.bqrs" 2>/dev/null | tail -n +2 | wc -l || echo "0")
        TOTAL_CODEQL=$((TOTAL_CODEQL + COUNT))

        # Mark high severity for taint tracking
        if [[ "$Q" == Tainted* ]]; then
            HIGH_SEVERITY=$((HIGH_SEVERITY + COUNT))
            echo -e "${RED}$COUNT results (${DURATION_Q}s) [HIGH]${NC}" | tee -a "$REPORT_FILE"
        else
            echo -e "${YELLOW}$COUNT results (${DURATION_Q}s)${NC}" | tee -a "$REPORT_FILE"
        fi
    done

    echo "" | tee -a "$REPORT_FILE"
    echo "CodeQL Summary:" | tee -a "$REPORT_FILE"
    echo "  Total findings: $TOTAL_CODEQL" | tee -a "$REPORT_FILE"
    echo "  High severity:  $HIGH_SEVERITY" | tee -a "$REPORT_FILE"
    echo "  End: $(date)" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# ========================================
# CHANNEL 2: libFuzzer Dynamic Fuzzing
# ========================================
run_fuzzer() {
    echo -e "${YELLOW}>>> Channel 2: libFuzzer Dynamic Fuzzing${NC}"
    echo "" | tee -a "$REPORT_FILE"
    echo "=== CHANNEL 2: LIBFUZZER DYNAMIC FUZZING ===" | tee -a "$REPORT_FILE"
    echo "Start: $(date)" | tee -a "$REPORT_FILE"
    echo "Duration: ${DURATION}s" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    BUILD_DIR="$FFMPEG_ROOT/fuzz-build"
    CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"
    CRASH_DIR="$FFMPEG_ROOT/fuzz-crashes"

    if [[ ! -d "$BUILD_DIR" ]]; then
        echo "ERROR: Fuzzer build not found. Run build_ffmpeg_fuzzer.sh first." | tee -a "$REPORT_FILE"
        echo "Fuzzer: SKIPPED (not built)" | tee -a "$REPORT_FILE"
        return 1
    fi

    mkdir -p "$CORPUS_DIR" "$CRASH_DIR"

    # Find available targets
    TARGETS=()
    for f in "$BUILD_DIR"/target_*_fuzzer; do
        if [[ -f "$f" && -x "$f" ]]; then
            TARGETS+=("$(basename "$f")")
        fi
    done

    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        echo "ERROR: No fuzz targets found in $BUILD_DIR" | tee -a "$REPORT_FILE"
        echo "Fuzzer: SKIPPED (no targets)" | tee -a "$REPORT_FILE"
        return 1
    fi

    echo "Available targets: ${TARGETS[*]}" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"

    TOTAL_CRASHES=0
    TOTAL_COVERAGE=0

    for TARGET in "${TARGETS[@]}"; do
        TARGET_NAME="${TARGET%_fuzzer}"
        TARGET_CORPUS="$CORPUS_DIR/$TARGET_NAME"
        TARGET_CRASH="$CRASH_DIR/$TARGET_NAME"
        mkdir -p "$TARGET_CORPUS" "$TARGET_CRASH"

        echo -n "  Fuzzing $TARGET... " | tee -a "$REPORT_FILE"

        # Run fuzzer with timeout
        timeout "${DURATION}s" "$BUILD_DIR/$TARGET" \
            -max_len=100000 \
            -max_total_time="$DURATION" \
            -artifact_prefix="$TARGET_CRASH/" \
            "$TARGET_CORPUS" \
            > "$CRASH_DIR/${TARGET_NAME}_fuzz.log" 2>&1 || true

        # Parse results
        CRASH_COUNT=$(ls -1 "$TARGET_CRASH"/crash-* 2>/dev/null | wc -l || echo "0")
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))

        # Extract coverage from log
        COV=$(grep -oP 'cov: \K\d+' "$CRASH_DIR/${TARGET_NAME}_fuzz.log" 2>/dev/null | tail -1 || echo "0")

        if [[ $CRASH_COUNT -gt 0 ]]; then
            echo -e "${RED}$CRASH_COUNT crashes, cov=$COV${NC}" | tee -a "$REPORT_FILE"
        else
            echo -e "${GREEN}no crashes, cov=$COV${NC}" | tee -a "$REPORT_FILE"
        fi
    done

    echo "" | tee -a "$REPORT_FILE"
    echo "Fuzzer Summary:" | tee -a "$REPORT_FILE"
    echo "  Total crashes: $TOTAL_CRASHES" | tee -a "$REPORT_FILE"
    echo "  End: $(date)" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# ========================================
# Run selected channels
# ========================================
case $CHANNEL in
    codeql) run_codeql ;;
    fuzzer) run_fuzzer ;;
    both)
        run_codeql
        echo "" | tee -a "$REPORT_FILE"
        run_fuzzer
        ;;
    *) echo "Unknown channel: $CHANNEL (use: codeql, fuzzer, both)"; exit 1 ;;
esac

# ========================================
# Final Summary
# ========================================
echo "========================================" | tee -a "$REPORT_FILE"
echo "  Dual-Channel Test Complete" | tee -a "$REPORT_FILE"
echo "  Finished: $(date)" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Next steps:" | tee -a "$REPORT_FILE"
echo "  1. Review CodeQL SARIF results in .joycode/" | tee -a "$REPORT_FILE"
echo "  2. Investigate fuzzer crashes in fuzz-crashes/" | tee -a "$REPORT_FILE"
echo "  3. Cross-reference findings between channels" | tee -a "$REPORT_FILE"
echo "  4. For longer fuzzing: bash .joycode/fuzz/run_fuzzer.sh --duration 86400" | tee -a "$REPORT_FILE"