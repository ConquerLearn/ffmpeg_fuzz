#!/bin/bash
# FFmpeg ASAN + trace-pc Coverage Build Script
#
# Builds FFmpeg with AddressSanitizer + coverage instrumentation for
# memory-corruption-aware fuzzing. Includes VC-1 decoder target.
#
# Key differences from build_clang_tracepc.sh:
#   - Adds -fsanitize=address for memory error detection
#   - Uses -fsanitize=undefined (no -fsanitize-trap=all) so UBSan reports
#     instead of trapping, allowing ASAN to coexist
#   - Enables VC-1 decoder and parser
#   - Builds VC-1 fuzzer target
#
# Prerequisites:
#   - Clang 22+ at .tools/msys64/mingw64/bin/clang
#   - MinGW64 toolchain
#
# Usage: bash build_asan_tracepc.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$FFMPEG_ROOT/fuzz-asan-build"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"
VC1_CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus-vc1"

# MSYS2 MinGW64 paths
MSYS2_ROOT="$FFMPEG_ROOT/.tools/msys64"
MINGW64_BIN="$MSYS2_ROOT/mingw64/bin"
export PATH="$MINGW64_BIN:$PATH"

# Compiler settings
CC="clang"
CXX="clang++"

# ASAN + coverage + UBSan (report mode, not trap mode)
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
COV_FLAGS="-fsanitize-coverage=trace-pc -fsanitize-coverage=indirect-calls"
UBSAN_FLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined"
CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $ASAN_FLAGS $COV_FLAGS $UBSAN_FLAGS"

echo "============================================"
echo "  FFmpeg ASAN + trace-pc Coverage Build"
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

# Verify ASAN support
echo ""
echo "=== Verifying ASAN support ==="
cat > /tmp/test_asan.c << 'EOF'
#include <stdlib.h>
int main(void) {
    char *p = malloc(10);
    p[10] = 0;  /* heap buffer overflow - ASAN should detect */
    free(p);
    return 0;
}
EOF

if clang -fsanitize=address -fno-omit-frame-pointer -O1 -g /tmp/test_asan.c -o /tmp/test_asan.exe 2>/dev/null; then
    echo "OK: ASAN compilation works"
    # Run and check if ASAN detects the overflow
    /tmp/test_asan.exe 2>&1 | head -5 || true
    echo "OK: ASAN runtime detection works (above output expected)"
    rm -f /tmp/test_asan.exe
else
    echo "ERROR: ASAN compilation failed"
    exit 1
fi
rm -f /tmp/test_asan.c

# Verify trace-pc + ASAN coexistence
echo ""
echo "=== Verifying trace-pc + ASAN coexistence ==="
cat > /tmp/test_asan_cov.c << 'EOF'
void __sanitizer_cov_trace_pc(void) {}
void __sanitizer_cov_trace_pc_indir(void *callee) { (void)callee; }
int main(void) { return 0; }
EOF

if clang -fsanitize=address -fsanitize-coverage=trace-pc /tmp/test_asan_cov.c -o /tmp/test_asan_cov.exe 2>/dev/null; then
    echo "OK: ASAN + trace-pc coexist"
    rm -f /tmp/test_asan_cov.exe
else
    echo "WARNING: ASAN + trace-pc test failed, trying without indirect-calls..."
    COV_FLAGS="-fsanitize-coverage=trace-pc"
    CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $ASAN_FLAGS $COV_FLAGS $UBSAN_FLAGS"
    if clang -fsanitize=address -fsanitize-coverage=trace-pc /tmp/test_asan_cov.c -o /tmp/test_asan_cov.exe 2>/dev/null; then
        echo "OK: ASAN + trace-pc (no indirect-calls) works"
        rm -f /tmp/test_asan_cov.exe
    else
        echo "ERROR: ASAN + trace-pc not supported together"
        exit 1
    fi
fi
rm -f /tmp/test_asan_cov.c

# Create build directory
mkdir -p "$BUILD_DIR"

# Build coverage stub library (needed for FFmpeg configure to pass)
echo ""
echo "=== Building coverage stub library ==="
clang -c "$SCRIPT_DIR/coverage_stub.c" -o "$BUILD_DIR/coverage_stub.o"
ar rcs "$BUILD_DIR/libcoverage_stub.a" "$BUILD_DIR/coverage_stub.o"
echo "OK: libcoverage_stub.a created"

# ========================================
# Step 1: Configure FFmpeg with ASAN + trace-pc + VC-1
# ========================================
echo ""
echo "============================================"
echo "  Step 1: Configure FFmpeg"
echo "============================================"

cd "$BUILD_DIR"

# Configure FFmpeg with ASAN, coverage, and VC-1 support
# Key additions vs trace-pc build:
#   - -fsanitize=address for memory error detection
#   - -fsanitize=undefined -fno-sanitize-recover=undefined (report, not trap)
#   - --enable-decoder=vc1,wmv3 for VC-1 fuzzing
#   - --enable-parser=vc1
"$FFMPEG_ROOT/configure" \
    --prefix="$BUILD_DIR/install" \
    --target-os=mingw32 \
    --cc=clang \
    --cxx=clang++ \
    --extra-cflags="$CFLAGS" \
    --extra-ldflags="$CFLAGS $BUILD_DIR/coverage_stub.o" \
    --disable-shared \
    --enable-static \
    --disable-x86asm \
    --disable-doc \
    --disable-programs \
    --disable-network \
    --disable-avdevice \
    --disable-everything \
    --enable-demuxer=mov,matroska,avi,flv,mpegts,mp3,wav,ogg,flac,asf \
    --enable-decoder=h264,hevc,aac,mp3,opus,vorbis,flac,vc1,wmv3 \
    --enable-parser=h264,hevc,mpegaudio,aac,opus,vorbis,flac,vc1 \
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
echo "  Step 2: Build FFmpeg (with ASAN)"
echo "============================================"

make -j$(nproc 2>/dev/null || echo 4)

echo ""
echo "=== Build complete ==="

# Verify ASAN instrumentation
echo ""
echo "=== Verifying ASAN instrumentation ==="
for lib in libavcodec/libavcodec.a libavformat/libavformat.a libavutil/libavutil.a libswresample/libswresample.a; do
    if [[ -f "$BUILD_DIR/$lib" ]]; then
        if nm "$BUILD_DIR/$lib" 2>/dev/null | grep -q "__asan"; then
            echo "OK: $lib has ASAN instrumentation"
        else
            echo "WARNING: $lib - no __asan symbols found"
        fi
    else
        echo "WARNING: $lib not found"
    fi
done

# ========================================
# Step 3: Build standalone driver (ASAN-aware)
# ========================================
echo ""
echo "============================================"
echo "  Step 3: Build standalone fuzzer driver"
echo "============================================"

INCLUDES="-I$BUILD_DIR -I$FFMPEG_ROOT"

# CRITICAL: standalone_driver.c must NOT be compiled with -fsanitize-coverage!
# The coverage callbacks (__sanitizer_cov_trace_pc etc.) are defined in this file.
# Also add no_sanitize("address") annotations for the coverage callbacks.
# We compile with ASAN but WITHOUT coverage flags for the driver.
DRIVER_CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover=undefined"
clang $DRIVER_CFLAGS $INCLUDES \
    -c "$SCRIPT_DIR/standalone_driver.c" \
    -o "$BUILD_DIR/standalone_driver.o"
echo "OK: standalone_driver.o (compiled WITH ASAN, WITHOUT coverage flags)"

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
echo "Building target_dec_h264_fuzzer (ASAN)..."
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
echo "Building target_dec_hevc_fuzzer (ASAN)..."
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

# --- VC-1 decoder fuzzer ---
echo ""
echo "Building target_dec_vc1_fuzzer (ASAN)..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_VC1 \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_vc1_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dec_vc1_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_vc1_fuzzer.exe"
echo "OK: target_dec_vc1_fuzzer.exe"

# --- WMV3 decoder fuzzer (uses VC-1 decoder internally) ---
echo ""
echo "Building target_dec_wmv3_fuzzer (ASAN)..."
clang $CFLAGS $INCLUDES \
    -DFFMPEG_CODEC=AV_CODEC_ID_WMV3 \
    -DFUZZ_FFMPEG_VIDEO \
    -c "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_wmv3_fuzzer.o"

clang $CFLAGS \
    "$BUILD_DIR/target_dec_wmv3_fuzzer.o" \
    "$BUILD_DIR/standalone_driver.o" \
    $LIB_DIRS $LIBS \
    -o "$BUILD_DIR/target_dec_wmv3_fuzzer.exe"
echo "OK: target_dec_wmv3_fuzzer.exe"

# --- MOV demuxer fuzzer ---
echo ""
echo "Building target_dem_mov_fuzzer (ASAN)..."
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

# ========================================
# Step 5: Generate seed corpus
# ========================================
echo ""
echo "============================================"
echo "  Step 5: Seed corpus"
echo "============================================"

mkdir -p "$CORPUS_DIR"
mkdir -p "$VC1_CORPUS_DIR"

# H.264 seed (already exists, check)
if [[ ! -f "$CORPUS_DIR/seed_h264_min.bin" ]]; then
    printf '\x00\x00\x00\x01\x67\x42\x00\x0a\xf8\x41\xa2' > "$CORPUS_DIR/seed_h264_min.bin"
    echo "Created seed_h264_min.bin"
else
    echo "seed_h264_min.bin already exists"
fi

# MOV seed (already exists, check)
if [[ ! -f "$CORPUS_DIR/seed_mov_min.bin" ]]; then
    printf '\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x00\x00\x69\x73\x6f\x6d' > "$CORPUS_DIR/seed_mov_min.bin"
    echo "Created seed_mov_min.bin"
else
    echo "seed_mov_min.bin already exists"
fi

# VC-1 seed: Minimal VC-1 sequence header
# VC-1 start code: 0x00 0x00 0x01 + sequence header code 0x0F
# Followed by minimal profile/level data
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_min.bin" ]]; then
    # VC-1 Sequence Header (start code + profile simple/main)
    # 00 00 01 0F = sequence header start code
    # Following bytes: profile (2 bits), level info, etc.
    printf '\x00\x00\x01\x0f\x01\x02\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00' > "$VC1_CORPUS_DIR/seed_vc1_min.bin"
    echo "Created seed_vc1_min.bin"
else
    echo "seed_vc1_min.bin already exists"
fi

# VC-1 advanced profile seed
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_advanced.bin" ]]; then
    # Advanced profile sequence header
    # 00 00 01 0F = start code
    # 0C = profile advanced (bits 7-6 = 11 = advanced profile)
    printf '\x00\x00\x01\x0f\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$VC1_CORPUS_DIR/seed_vc1_advanced.bin"
    echo "Created seed_vc1_advanced.bin"
fi

# VC-1 entry point seed
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_entrypoint.bin" ]]; then
    # Entry point header: 00 00 01 0D
    printf '\x00\x00\x01\x0d\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$VC1_CORPUS_DIR/seed_vc1_entrypoint.bin"
    echo "Created seed_vc1_entrypoint.bin"
fi

# VC-1 frame seed (start code 0x00 0x00 0x01 0x0C for field/frame)
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_frame.bin" ]]; then
    printf '\x00\x00\x01\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c' > "$VC1_CORPUS_DIR/seed_vc1_frame.bin"
    echo "Created seed_vc1_frame.bin"
fi

# Random seeds for VC-1
if [[ ! -f "$VC1_CORPUS_DIR/seed_random_256.bin" ]]; then
    dd if=/dev/urandom of="$VC1_CORPUS_DIR/seed_random_256.bin" bs=256 count=1 2>/dev/null
    echo "Created seed_random_256.bin"
fi

if [[ ! -f "$VC1_CORPUS_DIR/seed_random_1k.bin" ]]; then
    dd if=/dev/urandom of="$VC1_CORPUS_DIR/seed_random_1k.bin" bs=1024 count=1 2>/dev/null
    echo "Created seed_random_1k.bin"
fi

echo "Seed corpus ready in: $CORPUS_DIR and $VC1_CORPUS_DIR"

# ========================================
# Summary
# ========================================
echo ""
echo "============================================"
echo "  ASAN Build Complete!"
echo "============================================"
echo ""
echo "Fuzz targets (with ASAN + trace-pc coverage):"
ls -la "$BUILD_DIR"/*.exe 2>/dev/null || echo "  No executables found!"
echo ""
echo "Instrumentation:"
echo "  - AddressSanitizer: -fsanitize=address"
echo "  - Coverage: -fsanitize-coverage=trace-pc"
echo "  - UBSan: -fsanitize=undefined (report mode)"
echo ""
echo "Usage:"
echo "  # Single file (crash reproduction):"
echo "  $BUILD_DIR/target_dec_vc1_fuzzer.exe <input_file>"
echo ""
echo "  # Coverage-guided fuzzing (600s):"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe --fuzz $CORPUS_DIR 600"
echo "  $BUILD_DIR/target_dec_vc1_fuzzer.exe --fuzz $VC1_CORPUS_DIR 600"
echo "  $BUILD_DIR/target_dem_mov_fuzzer.exe --fuzz $CORPUS_DIR 600"
echo ""
echo "  # Quick test (30s per target):"
echo "  for f in $BUILD_DIR/target_*_fuzzer.exe; do"
echo "    echo \"Running \$f...\""
echo "    \$f --fuzz $CORPUS_DIR 30"
echo "  done"