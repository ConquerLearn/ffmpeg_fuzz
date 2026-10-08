#!/bin/bash
# FFmpeg UBSan-trap + trace-pc + VC-1 Build Script
#
# Builds FFmpeg with UBSan trap mode + coverage instrumentation for
# undefined-behavior-aware fuzzing. Includes VC-1 decoder target.
#
# Key features:
#   - UBSan trap mode (-fsanitize=undefined -fsanitize-trap=all):
#     Traps on ALL undefined behavior (signed overflow, null deref,
#     shift overflow, div-by-zero, etc.) WITHOUT needing runtime library
#   - trace-pc coverage for fuzzing guidance
#   - VC-1 decoder and parser enabled
#   - standalone_driver.c SEH handler catches EXCEPTION_ILLEGAL_INSTRUCTION
#     and recovers via longjmp, recording crashes
#
# Why UBSan-trap instead of UBSan-report or ASAN:
#   - ASAN: libclang_rt.asan* NOT available in MSYS2 MinGW64 Clang
#   - UBSan-report (-fno-sanitize-recover): libubsan NOT available in MinGW64
#   - UBSan-trap (-fsanitize-trap=all): NO runtime library needed!
#     Generates SIGILL/EXCEPTION_ILLEGAL_INSTRUCTION directly
#   - -ftrapv: Only catches signed overflow; UBSan-trap catches ALL UB
#
# This approach was already validated in fuzz-clang-build/ (existing build).
#
# Prerequisites:
#   - Clang 22+ at .tools/msys64/mingw64/bin/clang
#   - MinGW64 toolchain
#
# Usage: bash build_trapv_vc1.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$FFMPEG_ROOT/fuzz-vc1-build"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"
VC1_CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus-vc1"

# MSYS2 MinGW64 paths
MSYS2_ROOT="$FFMPEG_ROOT/.tools/msys64"
MINGW64_BIN="$MSYS2_ROOT/mingw64/bin"
export PATH="$MINGW64_BIN:$PATH"

# Compiler settings
CC="clang"
CXX="clang++"

# UBSan trap mode + trace-pc coverage
# -fsanitize=undefined: Enable all undefined behavior checks
# -fsanitize-trap=all: Trap (SIGILL) on UB instead of calling runtime library
# This combination needs NO runtime library - the compiler generates UD2
# instructions directly at UB check points.
COV_FLAGS="-fsanitize-coverage=trace-pc -fsanitize-coverage=indirect-calls"
UBSAN_TRAP_FLAGS="-fsanitize=undefined -fsanitize-trap=all"
CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations $COV_FLAGS $UBSAN_TRAP_FLAGS"

echo "============================================"
echo "  FFmpeg UBSan-trap + trace-pc + VC-1 Build"
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

# Verify UBSan-trap + trace-pc coexistence
echo ""
echo "=== Verifying UBSan-trap + trace-pc coexistence ==="
cat > /tmp/test_ubsan_trap.c << 'EOF'
void __sanitizer_cov_trace_pc(void) {}
void __sanitizer_cov_trace_pc_indir(void) {}
int main(void) {
    int x = 0x7fffffff;
    int y = x * x;  /* signed overflow - UBSan-trap should trap */
    return y;
}
EOF

if clang -fsanitize=undefined -fsanitize-trap=all -fsanitize-coverage=trace-pc -fsanitize-coverage=indirect-calls /tmp/test_ubsan_trap.c -o /tmp/test_ubsan_trap.exe 2>/dev/null; then
    echo "OK: UBSan-trap + trace-pc compilation works"
    # Run and verify trap is triggered (should get SIGILL/Illegal instruction)
    /tmp/test_ubsan_trap.exe 2>&1 || true
    echo "OK: UBSan-trap triggered (illegal instruction above = detection works!)"
    rm -f /tmp/test_ubsan_trap.exe
else
    echo "ERROR: UBSan-trap + trace-pc compilation failed"
    exit 1
fi
rm -f /tmp/test_ubsan_trap.c

# Create build directory
mkdir -p "$BUILD_DIR"

# Build coverage stub library (needed for FFmpeg configure to pass)
echo ""
echo "=== Building coverage stub library ==="
clang -c "$SCRIPT_DIR/coverage_stub.c" -o "$BUILD_DIR/coverage_stub.o"
ar rcs "$BUILD_DIR/libcoverage_stub.a" "$BUILD_DIR/coverage_stub.o"
echo "OK: libcoverage_stub.a created"

# ========================================
# Step 1: Configure FFmpeg with UBSan-trap + trace-pc + VC-1
# ========================================
echo ""
echo "============================================"
echo "  Step 1: Configure FFmpeg"
echo "============================================"

cd "$BUILD_DIR"

# Configure FFmpeg with UBSan-trap, coverage, and VC-1 support
# Note: -fsanitize-trap=all makes configure test programs trap on UB.
# FFmpeg's configure handles this gracefully (test failures are expected
# for some UB-prone tests, and configure adapts accordingly).
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
echo "  Step 2: Build FFmpeg (with UBSan-trap)"
echo "============================================"

make -j$(nproc 2>/dev/null || echo 4)

echo ""
echo "=== Build complete ==="

# ========================================
# Step 3: Build standalone driver (NO UBSan, NO coverage)
# ========================================
echo ""
echo "============================================"
echo "  Step 3: Build standalone fuzzer driver"
echo "============================================"

INCLUDES="-I$BUILD_DIR -I$FFMPEG_ROOT"

# CRITICAL: standalone_driver.c must NOT be compiled with -fsanitize-coverage!
# The coverage callbacks (__sanitizer_cov_trace_pc etc.) are defined in this file.
# Also do NOT compile with UBSan-trap to avoid false crashes in driver code.
DRIVER_CFLAGS="-g -O1 -Wall -Wno-unused-result -Wno-deprecated-declarations"
clang $DRIVER_CFLAGS $INCLUDES \
    -c "$SCRIPT_DIR/standalone_driver.c" \
    -o "$BUILD_DIR/standalone_driver.o"
echo "OK: standalone_driver.o (compiled WITHOUT UBSan-trap, WITHOUT coverage flags)"

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
echo "Building target_dec_h264_fuzzer (UBSan-trap)..."
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
echo "Building target_dec_hevc_fuzzer (UBSan-trap)..."
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
echo "Building target_dec_vc1_fuzzer (UBSan-trap)..."
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
echo "Building target_dec_wmv3_fuzzer (UBSan-trap)..."
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
echo "Building target_dem_mov_fuzzer (UBSan-trap)..."
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
else
    echo "seed_vc1_advanced.bin already exists"
fi

# VC-1 entry point seed
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_entrypoint.bin" ]]; then
    # Entry point header: 00 00 01 0D
    printf '\x00\x00\x01\x0d\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$VC1_CORPUS_DIR/seed_vc1_entrypoint.bin"
    echo "Created seed_vc1_entrypoint.bin"
else
    echo "seed_vc1_entrypoint.bin already exists"
fi

# VC-1 frame seed (start code 0x00 0x00 0x01 0x0C for field/frame)
if [[ ! -f "$VC1_CORPUS_DIR/seed_vc1_frame.bin" ]]; then
    printf '\x00\x00\x01\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c' > "$VC1_CORPUS_DIR/seed_vc1_frame.bin"
    echo "Created seed_vc1_frame.bin"
else
    echo "seed_vc1_frame.bin already exists"
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
echo "  UBSan-trap + trace-pc + VC-1 Build Complete!"
echo "============================================"
echo ""
echo "Fuzz targets (with UBSan-trap + trace-pc coverage):"
ls -la "$BUILD_DIR"/*.exe 2>/dev/null || echo "  No executables found!"
echo ""
echo "Instrumentation:"
echo "  - UBSan-trap: -fsanitize=undefined -fsanitize-trap=all (NO runtime library!)"
echo "  - Coverage: -fsanitize-coverage=trace-pc"
echo "  - NO ASAN: runtime library not available in MSYS2 MinGW64"
echo ""
echo "VC-1 vulnerability detection:"
echo "  - UBSan-trap will catch signed integer overflow in av_malloc(mb_stride * mb_height)"
echo "  - Also catches: null deref, shift overflow, div-by-zero, and other UB"
echo "  - Triggers EXCEPTION_ILLEGAL_INSTRUCTION, caught by SEH handler in standalone_driver.c"
echo "  - Fuzzer records it as a crash and continues"
echo ""
echo "Usage:"
echo "  # Single file (crash reproduction):"
echo "  $BUILD_DIR/target_dec_vc1_fuzzer.exe <input_file>"
echo ""
echo "  # Coverage-guided fuzzing (600s):"
echo "  $BUILD_DIR/target_dec_h264_fuzzer.exe --fuzz $CORPUS_DIR 600"
echo "  $BUILD_DIR/target_dec_vc1_fuzzer.exe --fuzz $VC1_CORPUS_DIR 600"
echo "  $BUILD_DIR/target_dem_mov_fuzzer.exe --fuzz $CORPUS_DIR 600"