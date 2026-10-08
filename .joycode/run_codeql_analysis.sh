#!/bin/bash
# FFmpeg CodeQL Automated Analysis Script
# Runs all custom CodeQL queries against the FFmpeg database
# Usage: bash run_codeql_analysis.sh [--quick|--full]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CODEQL_DB="$FFMPEG_ROOT/.codeql-db/cpp"
CODEQL_BIN="$FFMPEG_ROOT/.tools/codeql/codeql.exe"
QUERIES_DIR="$SCRIPT_DIR/queries"
RESULTS_DIR="$SCRIPT_DIR/results"
SARIF_DIR="$SCRIPT_DIR"

# Parse arguments
MODE="full"
if [[ "$1" == "--quick" ]]; then
    MODE="quick"
fi

echo "========================================"
echo "  FFmpeg CodeQL Automated Analysis"
echo "========================================"
echo "Database:  $CODEQL_DB"
echo "Queries:   $QUERIES_DIR"
echo "Results:   $RESULTS_DIR"
echo "Mode:      $MODE"
echo ""

# Verify database exists
if [[ ! -d "$CODEQL_DB" ]]; then
    echo "ERROR: CodeQL database not found at $CODEQL_DB"
    echo "Run 'codeql database create' first"
    exit 1
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

# Define queries to run
declare -A QUERIES
QUERIES["AvFreeUseAfterFreeV2"]="AvFreeUseAfterFreeV2.ql"
QUERIES["ResourceLeakErrorPathV2"]="ResourceLeakErrorPathV2.ql"
QUERIES["AVPacketLeak"]="AVPacketLeak.ql"
QUERIES["AVBufferRefImbalance"]="AVBufferRefImbalance.ql"
QUERIES["TaintedAllocSize"]="TaintedAllocSize.ql"
QUERIES["TaintedMemcpySize"]="TaintedMemcpySize.ql"
QUERIES["TaintedArrayIndex"]="TaintedArrayIndex.ql"

# Quick mode: only run taint tracking queries (high severity)
if [[ "$MODE" == "quick" ]]; then
    echo "Quick mode: Running only taint tracking queries"
    declare -A QUERIES
    QUERIES["TaintedAllocSize"]="TaintedAllocSize.ql"
    QUERIES["TaintedMemcpySize"]="TaintedMemcpySize.ql"
    QUERIES["TaintedArrayIndex"]="TaintedArrayIndex.ql"
fi

# Track total results
TOTAL_RESULTS=0
SUMMARY_FILE="$RESULTS_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"

echo "=== Running CodeQL Queries ===" | tee "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

for QUERY_NAME in "${!QUERIES[@]}"; do
    QUERY_FILE="$QUERIES_DIR/${QUERIES[$QUERY_NAME]}"
    OUTPUT_BQRS="$RESULTS_DIR/${QUERY_NAME}.bqrs"
    OUTPUT_SARIF="$SARIF_DIR/results-${QUERY_NAME,,}.sarif"

    if [[ ! -f "$QUERY_FILE" ]]; then
        echo "SKIP: $QUERY_NAME - query file not found: $QUERY_FILE"
        continue
    fi

    echo "----------------------------------------"
    echo "Running: $QUERY_NAME"
    echo "Query:   $QUERY_FILE"
    echo ""

    # Run query
    START_TIME=$(date +%s)
    "$CODEQL_BIN" database analyze "$CODEQL_DB" "$QUERY_FILE" \
        --output="$OUTPUT_BQRS" \
        --rerun 2>&1 | tail -5
    EXIT_CODE=$?
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo "ERROR: Query $QUERY_NAME failed (exit code $EXIT_CODE)"
        echo "$QUERY_NAME: FAILED (${DURATION}s)" >> "$SUMMARY_FILE"
        continue
    fi

    # Convert to SARIF
    "$CODEQL_BIN" bqrs decode --format=sarif-latest \
        --output="$OUTPUT_SARIF" "$OUTPUT_BQRS" 2>/dev/null || true

    # Count results
    RESULT_COUNT=$("$CODEQL_BIN" bqrs decode --format=csv "$OUTPUT_BQRS" 2>/dev/null | tail -n +2 | wc -l || echo "0")
    TOTAL_RESULTS=$((TOTAL_RESULTS + RESULT_COUNT))

    echo "Results: $RESULT_COUNT (took ${DURATION}s)"
    echo "$QUERY_NAME: $RESULT_COUNT results (${DURATION}s)" >> "$SUMMARY_FILE"
    echo ""
done

echo "========================================" | tee -a "$SUMMARY_FILE"
echo "  CodeQL Analysis Complete" | tee -a "$SUMMARY_FILE"
echo "  Total results: $TOTAL_RESULTS" | tee -a "$SUMMARY_FILE"
echo "  Mode: $MODE" | tee -a "$SUMMARY_FILE"
echo "========================================" | tee -a "$SUMMARY_FILE"
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo "SARIF files saved to: $SARIF_DIR/"

# Run built-in security queries if in full mode
if [[ "$MODE" == "full" ]]; then
    echo ""
    echo "=== Running CodeQL Built-in Security Suite ==="
    BUILTIN_SARIF="$RESULTS_DIR/builtin-security.sarif"
    "$CODEQL_BIN" database analyze "$CODEQL_DB" \
        codeql/cpp-queries:Security \
        --output="$RESULTS_DIR/builtin-security.bqrs" \
        --rerun 2>&1 | tail -10 || true
    echo "Built-in security analysis complete"
fi

echo ""
echo "All analysis complete!"