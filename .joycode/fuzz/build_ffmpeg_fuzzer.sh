#!/bin/bash
# FFmpeg libFuzzer Build Script
# Builds FFmpeg with clang and fuzzer instrumentation for libFuzzer
# Usage: bash build_ffmpeg_fuzzer.sh [target_dec|target_dem|target_bsf]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFMPEG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$FFMPEG_ROOT/fuzz-build"
INSTALL_DIR="$FFMPEG_ROOT/fuzz-install"
CORPUS_DIR="$FFMPEG_ROOT/fuzz-corpus"

# MSYS2 MinGW64 paths
MINGW64_BIN="/mingw64/bin"
export PATH="$MINGW64_BIN:$PATH"

# Compiler flags for fuzzing
FUZZ_FLAGS="-fsanitize=fuzzer-no-link -fsanitize=address -g -O1"
FUZZ_LDFLAGS="-fsanitize=fuzzer"

echo "=== FFmpeg libFuzzer Build Script ==="
echo "FFmpeg root: $FFMPEG_ROOT"
echo "Build dir:   $BUILD_DIR"
echo "Install dir: $INSTALL_DIR"

# Create build directory
mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$CORPUS_DIR"

cd "$BUILD_DIR"

# Configure FFmpeg
echo ""
echo "=== Configuring FFmpeg with fuzzer instrumentation ==="
CC="clang $FUZZ_FLAGS" \
CXX="clang++ $FUZZ_FLAGS" \
LDFLAGS="$FUZZ_FLAGS" \
"$FFMPEG_ROOT/configure" \
    --prefix="$INSTALL_DIR" \
    --cc=clang \
    --cxx=clang++ \
    --extra-cflags="$FUZZ_FLAGS" \
    --extra-ldflags="$FUZZ_LDFLAGS" \
    --disable-shared \
    --enable-static \
    --disable-x86asm \
    --disable-doc \
    --disable-programs \
    --disable-network \
    --disable-everything \
    --enable-demuxer=mov,matroska,avi,flv,mpegts,mp3,wav,ogg,flac \
    --enable-decoder=h264,hevc,av1,vp9,vp8,mpeg4,mpeg2video,aac,mp3,opus,vorbis,flac \
    --enable-parser=h264,hevc,av1,vp9,vp8,mpeg4video,mpegaudio,aac,opus,vorbis,flac \
    --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb,aac_adtstoasc \
    --enable-protocol=file \
    --enable-swresample \
    --enable-swscale \
    --enable-avcodec \
    --enable-avformat \
    --enable-avutil

echo ""
echo "=== Building FFmpeg ==="
make -j$(nproc)

echo ""
echo "=== Installing FFmpeg ==="
make install

echo ""
echo "=== Building fuzz targets ==="

# Build decoder fuzzer
echo "Building target_dec_fuzzer..."
clang $FUZZ_FLAGS -fsanitize=fuzzer \
    -I"$INSTALL_DIR/include" \
    -DFFMPEG_CODEC=AV_CODEC_ID_H264 -DFUZZ_FFMPEG_VIDEO \
    "$FFMPEG_ROOT/tools/target_dec_fuzzer.c" \
    -o "$BUILD_DIR/target_dec_h264_fuzzer" \
    -L"$INSTALL_DIR/lib" \
    -lavformat -lavcodec -lswresample -lswscale -lavutil \
    -lm -lpthread -lws2_32 -lsecur32 -lbcrypt

# Build demuxer fuzzer
echo "Building target_dem_fuzzer..."
clang $FUZZ_FLAGS -fsanitize=fuzzer \
    -I"$INSTALL_DIR/include" \
    -DFFMPEG_DEMUXER=mov \
    "$FFMPEG_ROOT/tools/target_dem_fuzzer.c" \
    -o "$BUILD_DIR/target_dem_mov_fuzzer" \
    -L"$INSTALL_DIR/lib" \
    -lavformat -lavcodec -lswresample -lswscale -lavutil \
    -lm -lpthread -lws2_32 -lsecur32 -lbcrypt

# Build BSF fuzzer
echo "Building target_bsf_fuzzer..."
clang $FUZZ_FLAGS -fsanitize=fuzzer \
    -I"$INSTALL_DIR/include" \
    "$FFMPEG_ROOT/tools/target_bsf_fuzzer.c" \
    -o "$BUILD_DIR/target_bsf_fuzzer" \
    -L"$INSTALL_DIR/lib" \
    -lavformat -lavcodec -lswresample -lswscale -lavutil \
    -lm -lpthread -lws2_32 -lsecur32 -lbcrypt

echo ""
echo "=== Build complete! ==="
echo "Fuzz targets in: $BUILD_DIR/"
echo "Corpus dir:      $CORPUS_DIR/"
echo ""
echo "To run fuzzing:"
echo "  cd $BUILD_DIR"
echo "  ./target_dec_h264_fuzzer -max_len=100000 -max_total_time=3600 $CORPUS_DIR"
echo "  ./target_dem_mov_fuzzer -max_len=100000 -max_total_time=3600 $CORPUS_DIR"