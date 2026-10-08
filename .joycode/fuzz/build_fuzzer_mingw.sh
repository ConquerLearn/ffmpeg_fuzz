#!/bin/bash
# FFmpeg Fuzzer Build Script for MinGW (Windows)
# 
# Uses pre-built FFmpeg libraries from CodeQL build + standalone driver
# to avoid the -fsanitize=fuzzer-no-link MinGW limitation.
#
# Usage: bash build_fuzzer_mingw.sh
#
# This creates fuzz targets that can be run in two modes:
#   ./target_dec_h264_fuzzer.exe <input_file>     - Single file (crash repro)
#   ./target_dec_h264_fuzzer.exe --fuzz <dir> <s> - Mutation fuzzing

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CODEQL_BUILD="$FFMPEG_ROOT/.codeql-build"
BUILD_DIR="$FFMPEG_ROOT/fuzz-build"
INSTALL_DIR="$FFMPEG_ROOT/fuzz-install"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"

# MinGW64 paths (from .tools/msys64)
MSYS2_ROOT="$FFMPEG_ROOT/.tools/msys64"
MINGW64_BIN="$MSYS2_ROOT/mingw64/bin"
export PATH="$MINGW64_BIN:$PATH"

echo "============================================"
echo "  FFmpeg Fuzzer Build (MinGW Standalone)"
echo "============================================"
echo "FFmpeg root:    $FFMPEG_ROOT"
echo "CodeQL build:   $CODEQL_BUILD"
echo "Build dir:      $BUILD_DIR"
echo ""

# Check prerequisites
if [[ ! -f "$CODEQL_BUILD/libavcodec/libavcodec.a" ]]; then
    echo "ERROR: CodeQL-built FFmpeg libraries not found in $CODEQL_BUILD"
    echo "Please run CodeQL database creation first."
    exit 1
fi

if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found. Ensure MinGW64 bin is in PATH."
    exit 1
fi

echo "=== GCC version ==="
gcc --version | head -1

# Create directories
mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$CORPUS_DIR"

# Copy config headers
cp "$CODEQL_BUILD/config.h" "$BUILD_DIR/" 2>/dev/null || true
cp "$CODEQL_BUILD/config_components.h" "$BUILD_DIR/" 2>/dev/null || true
cp -r "$CODEQL_BUILD/ffbuild" "$BUILD_DIR/" 2>/dev/null || true

# Compiler flags
CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations"
INCLUDES="-I$CODEQL_BUILD -I$FFMPEG_ROOT"

# Library paths and link flags
LIB_DIRS="-L$CODEQL_BUILD/libavformat -L$CODEQL_BUILD/libavcodec -L$CODEQL_BUILD/libswresample -L$CODEQL_BUILD/libswscale -L$CODEQL_BUILD/libavutil -L$CODEQL_BUILD/libavfilter"
LIBS="-lavformat -lavcodec -lswresample -lswscale -lavutil -lm -lpthread -lws2_32 -lsecur32 -lbcrypt -lole32 -lshell32 -lshlwapi"

# ========================================
# Build standalone driver
# ========================================
echo ""
echo "=== Building standalone fuzzer driver ==="
gcc $CFLAGS $INCLUDES -c "$SCRIPT_DIR/standalone_driver.c" -o "$BUILD_DIR/standalone_driver.o"
echo "OK: standalone_driver.o"

# ========================================
# Build decoder fuzzer (H.264)
# ========================================
echo ""
echo "=== Building target_dec_h264_fuzzer ==="
gcc $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_H264 \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_h264_fuzzer.o"
echo "OK: target_dec_h264_fuzzer.o"

gcc $CFLAGS \
    "$BUILD_DIR/target_dec_h264_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_h264_fuzzer.exe"
echo "OK: target_dec_h264_fuzzer.exe"

# ========================================
# Build decoder fuzzer (HEVC)
# ========================================
echo ""
echo "=== Building target_dec_hevc_fuzzer ==="
gcc $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_HEVC \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_hevc_fuzzer.o"

gcc $CFLAGS \
    "$BUILD_DIR/target_dec_hevc_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_hevc_fuzzer.exe"
echo "OK: target_dec_hevc_fuzzer.exe"

# ========================================
# Build decoder fuzzer (AAC)
# ========================================
echo ""
echo "=== Building target_dec_aac_fuzzer ==="
gcc $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_AAC \
    -DFUZZ_FFMPEG_AUDIO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_aac_fuzzer.o"

gcc $CFLAGS \
    "$BUILD_DIR/target_dec_aac_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_aac_fuzzer.exe"
echo "OK: target_dec_aac_fuzzer.exe"

# ========================================
# Build demuxer fuzzer (MOV)
# ========================================
echo ""
echo "=== Building target_dem_mov_fuzzer ==="
gcc $CFLAGS $INCLUDES \
    -DFFMPEG_DEMUXER=mov \
    -c "$FFMPEG_ROOT/tools/target_dem_fuzzer.c" \
    -o "$BUILD_DIR/target_dem_mov_fuzzer.o"

gcc $CFLAGS \
    "$BUILD_DIR/target_dem_mov_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dem_mov_fuzzer.exe"
echo "OK: target_dem_mov_fuzzer.exe"

# ========================================
# Build BSF fuzzer (h264_mp4toannexb)
# ========================================
echo ""
echo "=== Building target_bsf_h264_fuzzer ==="
gcc $CFLAGS $INCLUDES \
    -DFFMPEG_BSF=h264_mp4toannexb \
    -c "$FFMPEG_ROOT/tools/target_bsf_fuzzer.c" \
    -o "$BUILD_DIR/target_bsf_h264_fuzzer.o"

gcc $CFLAGS \
    "$BUILD_DIR/target_bsf_h264_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_bsf_h264_fuzzer.exe"
echo "OK: target_bsf_h264_fuzzer.exe"

# ========================================
# Generate seed corpus
# ========================================
echo ""
echo "=== Generating seed corpus ==="

# Minimal H.264 NAL unit (SPS)
printf '\x00\x00\x00\x01\x67\x42\x00\x0a\xf8\x41\xa2' > "$CORPUS_DIR/seed_h264_min.bin"
# Minimal MOV container (ftyp box)
printf '\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x00\x00\x69\x73\x6f\x6d' > "$CORPUS_DIR/seed_mov_min.bin"
# Minimal AAC ADTS frame
printf '\xff\xf1\x50\x40\x00\x1f\xfc\x21\x00\x00\x00\x00\x00\x00\x00\x00' > "$CORPUS_DIR/seed_aac_min.bin"
# Random seeds
dd if=/dev/urandom of="$CORPUS_DIR/seed_random_256.bin" bs=256 count=1 2>/dev/null
dd if=/dev/urandom of="$CORPUS_DIR/seed_random_1k.bin" bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of="$CORPUS_DIR/seed_random_4k.bin" bs=4096 count=1 2>/dev/null

echo "Seed corpus created in: $CORPUS_DIR"

# ========================================
# Summary
# ========================================
echo ""
echo "============================================"
echo "  Build Complete!"
echo "============================================"
echo ""
echo "Fuzz targets:"
ls -la "$BUILD_DIR"/*.exe 2>/dev/null || echo "  No executables found!"
echo ""
echo "Seed corpus:"
ls -la "$CORPUS_DIR/" 2>/dev/null | head -10
echo ""
echo "Usage:"
echo "  # Single file (crash reproduction):"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe <input_file>"
echo ""
echo "  # Mutation-based fuzzing:"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe --fuzz $CORPUS_DIR 60"
echo ""
echo "  # Run all fuzzers for 5 minutes each:"
echo "  for f in $BUILD_DIR/target_*_fuzzer.exe; do"
echo "    echo \"Running: \$f\""
echo "    \$f --fuzz $CORPUS_DIR 300"
echo "  done"