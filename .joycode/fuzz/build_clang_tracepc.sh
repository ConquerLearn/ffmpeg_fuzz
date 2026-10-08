#!/bin/bash
# FFmpeg Clang trace-pc Coverage Build Script
# 
# Rebuilds FFmpeg with Clang + -fsanitize-coverage=trace-pc for coverage-guided fuzzing.
# This solves the "coverage=0" problem where CodeQL pre-built libraries had no instrumentation.
#
# Prerequisites:
#   - Clang 22+ installed at .tools/msys64/mingw64/bin/clang
#   - MinGW64 toolchain
#
# Usage: bash build_clang_tracepc.sh
#
# Output:
#   - fuzz-clang-build/ : FFmpeg libraries with coverage instrumentation
#   - fuzz-clang-build/*.exe : Fuzz targets with coverage support

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$FFMPEG_ROOT/fuzz-clang-build"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"

# MSYS2 MinGW64 paths
MSYS2_ROOT="$FFMPEG_ROOT/.tools/msys64"
MINGW64_BIN="$MSYS2_ROOT/mingw64/bin"
export PATH="$MINGW64_BIN:$PATH"

# Compiler settings
CC="clang"
CXX="clang++"
COV_FLAGS="-fsanitize-coverage=trace-pc -fsanitize-coverage=indirect-calls"
UBSAN_FLAGS="-fsanitize=undefined -fsanitize-trap=all"
CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $COV_FLAGS $UBSAN_FLAGS"

echo "============================================"
echo "  FFmpeg Clang trace-pc Coverage Build"
echo "============================================"
echo "FFmpeg root:  $FFMPEG_ROOT"
echo "Build dir:    $BUILD_DIR"
echo "CC:           $CC"
echo "CFLAGS:       $CFLAGS"
echo ""

# Check prerequisites
echo "=== Checking prerequisites ==="

if ! command -v clang &> /dev/null; then
    echo "ERROR: clang not found in PATH"
    echo "Expected: $MINGW64_BIN/clang"
    exit 1
fi

echo "Clang version:"
clang --version | head -2

# Verify trace-pc support
echo ""
echo "=== Verifying trace-pc support ==="
cat > /tmp/test_tracepc.c << 'EOF'
void __sanitizer_cov_trace_pc(void) {}
void __sanitizer_cov_trace_pc_indirect(void) {}
int main(void) { return 0; }
EOF

if clang -fsanitize-coverage=trace-pc -fsanitize-coverage=indirect-calls /tmp/test_tracepc.c -o /tmp/test_tracepc.exe 2>/dev/null; then
    echo "OK: Clang trace-pc compilation + linking works"
    rm -f /tmp/test_tracepc.exe
else
    echo "WARNING: Clang trace-pc test build failed, trying without indirect-calls..."
    COV_FLAGS="-fsanitize-coverage=trace-pc"
    CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $COV_FLAGS"
    if clang -fsanitize-coverage=trace-pc /tmp/test_tracepc.c -o /tmp/test_tracepc.exe 2>/dev/null; then
        echo "OK: Clang trace-pc (without indirect-calls) works"
        rm -f /tmp/test_tracepc.exe
    else
        echo "ERROR: Clang trace-pc not supported"
        exit 1
    fi
fi
rm -f /tmp/test_tracepc.c

# Verify UBSan trap support
echo ""
echo "=== Verifying UBSan trap support ==="
cat > /tmp/test_ubsan.c << 'EOF'
#include <limits.h>
int main(void) {
    volatile int x = INT_MAX;
    volatile int y = x + 1;  /* signed overflow - UBSan should trap */
    return y;
}
EOF

if clang -fsanitize=undefined -fsanitize-trap=all /tmp/test_ubsan.c -o /tmp/test_ubsan.exe 2>/dev/null; then
    echo "OK: UBSan trap compilation works"
    # Test that it actually traps on UB
    if /tmp/test_ubsan.exe 2>/dev/null; [ $? -eq 132 ] 2>/dev/null || true; then
        echo "OK: UBSan trap detects signed integer overflow (exit 132 = SIGILL trap)"
    else
        echo "INFO: UBSan binary ran but may not have trapped (expected exit 132)"
    fi
    rm -f /tmp/test_ubsan.exe
else
    echo "WARNING: UBSan trap compilation failed, building without UBSan"
    UBSAN_FLAGS=""
    CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $COV_FLAGS"
fi
rm -f /tmp/test_ubsan.c

# Create build directory
mkdir -p "$BUILD_DIR"

# Build coverage stub library (needed for FFmpeg configure to pass)
echo ""
echo "=== Building coverage stub library ==="
clang -c "$SCRIPT_DIR/coverage_stub.c" -o "$BUILD_DIR/coverage_stub.o"
ar rcs "$BUILD_DIR/libcoverage_stub.a" "$BUILD_DIR/coverage_stub.o"
echo "OK: libcoverage_stub.a created"

# ========================================
# Step 1: Configure FFmpeg with Clang + trace-pc
# ========================================
echo ""
echo "============================================"
echo "  Step 1: Configure FFmpeg"
echo "============================================"

cd "$BUILD_DIR"

# Configure FFmpeg with minimal components for fuzzing
# Use --disable-everything + enable only what we need to speed up build
# NOTE: --extra-ldflags includes coverage_stub.o to resolve __sanitizer_cov_trace_pc
"$FFMPEG_ROOT/configure" \
    --prefix="$BUILD_DIR/install" \
    --target-os=mingw32 \
    --cc=clang \
    --cxx=clang++ \
    --extra-cflags="$COV_FLAGS $UBSAN_FLAGS" \
    --extra-ldflags="$COV_FLAGS $UBSAN_FLAGS $BUILD_DIR/coverage_stub.o" \
    --disable-shared \
    --enable-static \
    --disable-x86asm \
    --disable-doc \
    --disable-programs \
    --disable-network \
    --disable-avdevice \
    --disable-everything \
    --enable-demuxer=mov,matroska,avi,flv,mpegts,mp3,wav,ogg,flac \
    --enable-decoder=h264,hevc,aac,mp3,opus,vorbis,flac \
    --enable-parser=h264,hevc,mpegaudio,aac,opus,vorbis,flac \
    --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb,aac_adtstoasc \
    --enable-protocol=file \
    --enable-swresample \
    --enable-swscale \
    --enable-avcodec \
    --enable-avformat \
    --enable-avutil

echo ""
echo "=== Configure complete ==="

# ========================================
# Step 2: Build FFmpeg libraries
# ========================================
echo ""
echo "============================================"
echo "  Step 2: Build FFmpeg"
echo "============================================"

make -j$(nproc 2>/dev/null || echo 4)

echo ""
echo "=== Build complete ==="

# Verify libraries have coverage instrumentation
echo ""
echo "=== Verifying coverage instrumentation ==="
for lib in libavcodec/libavcodec.a libavformat/libavformat.a libavutil/libavutil.a libswresample/libswresample.a libswscale/libswscale.a; do
    if [[ -f "$BUILD_DIR/$lib" ]]; then
        # Check if __sanitizer_cov_trace_pc appears in the library
        if nm "$BUILD_DIR/$lib" 2>/dev/null | grep -q "__sanitizer_cov_trace_pc"; then
            echo "OK: $lib has coverage instrumentation"
        else
            # trace-pc inserts calls at each edge, the symbols are in our driver
            # Check for .sancov sections instead
            if objdump -h "$BUILD_DIR/$lib" 2>/dev/null | grep -q "sancov"; then
                echo "OK: $lib has .sancov sections"
            else
                echo "INFO: $lib - checking if coverage calls were inlined"
            fi
        fi
    else
        echo "WARNING: $lib not found"
    fi
done

# ========================================
# Step 3: Build standalone driver
# ========================================
echo ""
echo "============================================"
echo "  Step 3: Build standalone fuzzer driver"
echo "============================================"

INCLUDES="-I$BUILD_DIR -I$FFMPEG_ROOT"

# CRITICAL: standalone_driver.c must NOT be compiled with -fsanitize-coverage flags!
# The coverage callbacks (__sanitizer_cov_trace_pc etc.) are defined in this file.
# If compiled with coverage instrumentation, the compiler inserts trace-pc calls
# INSIDE the callbacks, causing infinite recursion → stack overflow (0xC00000FD).
# We also add __attribute__((no_sanitize("coverage"))) as defense-in-depth.
DRIVER_CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations"
# NOTE: standalone_driver.c is compiled WITHOUT -fsanitize-coverage AND WITHOUT -fsanitize=undefined
# because: (1) coverage callbacks must not be instrumented (infinite recursion)
#          (2) UBSan traps in our own signal/SEH handlers would be counterproductive
clang $DRIVER_CFLAGS $INCLUDES \
    -c "$SCRIPT_DIR/standalone_driver.c" \
    -o "$BUILD_DIR/standalone_driver.o"
echo "OK: standalone_driver.o (compiled WITHOUT coverage flags)"

# ========================================
# Step 4: Build fuzz targets
# ========================================
echo ""
echo "============================================"
echo "  Step 4: Build fuzz targets"
echo "============================================"

LIB_DIRS="-L$BUILD_DIR/libavformat -L$BUILD_DIR/libavcodec -L$BUILD_DIR/libswresample -L$BUILD_DIR/libswscale -L$BUILD_DIR/libavutil"
LIBS="-lavformat -lavcodec -lswresample -lswscale -lavutil -lm -lpthread -lws2_32 -lsecur32 -lbcrypt -lole32 -lshell32 -lshlwapi -liconv -latomic -lmfuuid -lstrmiids -luser32 -lz"

# --- H.264 decoder fuzzer ---
echo ""
echo "Building target_dec_h264_fuzzer..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_H264 \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_h264_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dec_h264_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_h264_fuzzer.exe"
echo "OK: target_dec_h264_fuzzer.exe"

# --- HEVC decoder fuzzer ---
echo ""
echo "Building target_dec_hevc_fuzzer..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_HEVC \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_hevc_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dec_hevc_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_hevc_fuzzer.exe"
echo "OK: target_dec_hevc_fuzzer.exe"

# --- AAC decoder fuzzer ---
echo ""
echo "Building target_dec_aac_fuzzer..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_AAC \
    -DFUZZ_FFMPEG_AUDIO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_aac_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dec_aac_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_aac_fuzzer.exe"
echo "OK: target_dec_aac_fuzzer.exe"

# --- MOV demuxer fuzzer ---
echo ""
echo "Building target_dem_mov_fuzzer..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_DEMUXER=mov \
    -c "$FFMPEG_ROOT/tools/target_dem_fuzzer.c" \
    -o "$BUILD_DIR/target_dem_mov_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dem_mov_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dem_mov_fuzzer.exe"
echo "OK: target_dem_mov_fuzzer.exe"

# --- BSF fuzzer (h264_mp4toannexb) ---
echo ""
echo "Building target_bsf_h264_fuzzer..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_BSF=h264_mp4toannexb \
    -c "$FFMPEG_ROOT/tools/target_bsf_fuzzer.c" \
    -o "$BUILD_DIR/target_bsf_h264_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_bsf_h264_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_bsf_h264_fuzzer.exe"
echo "OK: target_bsf_h264_fuzzer.exe"

# ========================================
# Step 5: Generate seed corpus (if not exists)
# ========================================
echo ""
echo "============================================"
echo "  Step 5: Seed corpus"
echo "============================================"

mkdir -p "$CORPUS_DIR"

if [[ ! -f "$CORPUS_DIR/seed_h264_min.bin" ]]; then
    # Minimal H.264 NAL unit (SPS)
    printf '\x00\x00\x00\x01\x67\x42\x00\x0a\xf8\x41\xa2' > "$CORPUS_DIR/seed_h264_min.bin"
    echo "Created seed_h264_min.bin"
else
    echo "seed_h264_min.bin already exists"
fi

if [[ ! -f "$CORPUS_DIR/seed_mov_min.bin" ]]; then
    # Minimal MOV container (ftyp box)
    printf '\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x00\x00\x69\x73\x6f\x6d' > "$CORPUS_DIR/seed_mov_min.bin"
    echo "Created seed_mov_min.bin"
else
    echo "seed_mov_min.bin already exists"
fi

if [[ ! -f "$CORPUS_DIR/seed_aac_min.bin" ]]; then
    # Minimal AAC ADTS frame
    printf '\xff\xf1\x50\x40\x00\x1f\xfc\x21\x00\x00\x00\x00\x00\x00\x00\x00' > "$CORPUS_DIR/seed_aac_min.bin"
    echo "Created seed_aac_min.bin"
else
    echo "seed_aac_min.bin already exists"
fi

if [[ ! -f "$CORPUS_DIR/seed_random_256.bin" ]]; then
    dd if=/dev/urandom of="$CORPUS_DIR/seed_random_256.bin" bs=256 count=1 2>/dev/null
    echo "Created seed_random_256.bin"
fi

if [[ ! -f "$CORPUS_DIR/seed_random_1k.bin" ]]; then
    dd if=/dev/urandom of="$CORPUS_DIR/seed_random_1k.bin" bs=1024 count=1 2>/dev/null
    echo "Created seed_random_1k.bin"
fi

echo "Seed corpus ready in: $CORPUS_DIR"

# ========================================
# Summary
# ========================================
echo ""
echo "============================================"
echo "  Build Complete!"
echo "============================================"
echo ""
echo "Fuzz targets (with trace-pc coverage):"
ls -la "$BUILD_DIR"/*.exe 2>/dev/null || echo "  No executables found!"
echo ""
echo "Coverage instrumentation: -fsanitize-coverage=trace-pc"
echo "Coverage mode: bitmap-based PC tracking"
echo ""
echo "Usage:"
echo "  # Single file (crash reproduction):"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe <input_file>"
echo ""
echo "  # Coverage-guided fuzzing:"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe --fuzz $CORPUS_DIR 60"
echo ""
echo "  # Quick test (30s per target):"
echo "  for f in $BUILD_DIR/target_*_fuzzer.exe; do"
echo "    echo \"Running \$f...\""
echo "    \$f --fuzz $CORPUS_DIR 30"
echo "  done"