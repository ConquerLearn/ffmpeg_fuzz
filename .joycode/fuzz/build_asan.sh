#!/bin/bash
# Build FFmpeg with AddressSanitizer for enhanced fuzzing
# This enables runtime detection of memory corruption bugs

set -e

WORKSPACE="/c/Users/Administrator/Desktop/1/8-6/FFmpeg-release-8.1"
SRC_DIR="$WORKSPACE"
BUILD_DIR="$WORKSPACE/.asan-build"
FUZZ_DIR="$WORKSPACE/.joycode/fuzz"
FUZZ_BUILD="$WORKSPACE/fuzz-build"

# MinGW64 toolchain
export PATH="/mingw64/bin:$PATH"
export CC=gcc
export CXX=g++

echo "=== FFmpeg ASan Build Script ==="
echo "Source: $SRC_DIR"
echo "Build:  $BUILD_DIR"

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure FFmpeg with AddressSanitizer
echo ""
echo "=== Step 1: Configuring FFmpeg with ASan ==="

# ASan flags
ASAN_CFLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g"
ASAN_LDFLAGS="-fsanitize=address"

"$SRC_DIR/configure" \
    --disable-doc \
    --disable-programs \
    --disable-avdevice \
    --disable-network \
    --disable-x86asm \
    --disable-asm \
    --enable-debug \
    --extra-cflags="$ASAN_CFLAGS" \
    --extra-cxxflags="$ASAN_CFLAGS" \
    --extra-ldflags="$ASAN_LDFLAGS" \
    --build_suffix=_asan

echo ""
echo "=== Step 2: Building FFmpeg libraries with ASan ==="
make -j$(nproc) 2>&1 | tail -20

echo ""
echo "=== Step 3: Building fuzz targets with ASan ==="

# Common flags for fuzz targets
COMMON_CFLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g -DIO_FLAT=0"
COMMON_LDFLAGS="-fsanitize=address"

# Library paths
LIB_DIRS="-L$BUILD_DIR/libavcodec -L$BUILD_DIR/libavformat -L$BUILD_DIR/libavutil -L$BUILD_DIR/libswresample -L$BUILD_DIR/libswscale -L$BUILD_DIR/libavfilter"
INCLUDE_DIRS="-I$SRC_DIR -I$BUILD_DIR"

# External libs from config
EXT_LIBS="-liconv -lz -lm -latomic -lmfuuid -lole32 -lstrmiids -lstdc++ -luser32 -lbcrypt"

build_fuzzer() {
    local name=$1
    local target_src=$2
    local libs=$3
    
    echo "Building $name..."
    gcc $COMMON_CFLAGS $INCLUDE_DIRS -c "$FUZZ_DIR/standalone_driver.c" -o "$FUZZ_BUILD/standalone_driver_asan.o" 2>&1
    gcc $COMMON_CFLAGS $INCLUDE_DIRS -c "$SRC_DIR/tools/target_$target_src" -o "$FUZZ_BUILD/${name}_asan.o" 2>&1
    gcc $COMMON_LDFLAGS $FUZZ_BUILD/standalone_driver_asan.o $FUZZ_BUILD/${name}_asan.o \
        $LIB_DIRS $libs $EXT_LIBS \
        -o "$FUZZ_BUILD/${name}_asan.exe" 2>&1
    echo "  -> $FUZZ_BUILD/${name}_asan.exe"
}

# Build each fuzzer
build_fuzzer "target_dec_h264_fuzzer" "dec_fuzzer.c" "-lavcodec_asan -lswresample_asan -lavutil_asan"
build_fuzzer "target_dec_hevc_fuzzer" "dec_fuzzer.c" "-lavcodec_asan -lswresample_asan -lavutil_asan"
build_fuzzer "target_dec_aac_fuzzer" "dec_fuzzer.c" "-lavcodec_asan -lswresample_asan -lavutil_asan"
build_fuzzer "target_dem_mov_fuzzer" "dem_fuzzer.c" "-lavformat_asan -lavcodec_asan -lswresample_asan -lavutil_asan"
build_fuzzer "target_bsf_h264_fuzzer" "bsf_fuzzer.c" "-lavcodec_asan -lswresample_asan -lavutil_asan"

echo ""
echo "=== ASan Build Complete ==="
ls -la "$FUZZ_BUILD"/*_asan.exe 2>/dev/null || echo "No ASan executables found"