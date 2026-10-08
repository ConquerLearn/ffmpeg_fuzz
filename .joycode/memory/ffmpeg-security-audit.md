---
name: ffmpeg-security-audit
description: FFmpeg 8.1安全审计结论(含UBSan-trap fuzzing动态验证)
type: project
---

VC-1 unsafe av_malloc(vc1dec.c:366)理论漏洞但实际不可利用: UBSan-trap fuzzing 600s×2轮0 crash/0 UBSan trap; maxpixels限制(maxpixels_per_frame=16,384,000)阻止int*int溢出触发. Why: target_dec_fuzzer.c:329 maxpixels/=8192限制. How to apply: 风险评级低,建议防御性修复av_malloc_array. 注意非fuzzer路径可能仍可触发. H.264 9个crash均为av_assert0(AVERROR_BUG)非安全漏洞. MOV 72处UAF全部误报. Fuzzing: UBSan-trap+trace-pc, MinGW, -Wl,-w抑制drectve, -DIO_FLAT=0. VC-1专用seed(7个)→覆盖11x提升(409→4489).

MOV crash_1.bin根因: mov_parse_stsd_audio() mov.c:2812 `st->codecpar->sample_rate=av_int2double(avio_rb64(pb))` — QT version 2格式sample_rate从double隐式转int溢出UB. ASAN验证无内存安全问题. Exception Code 0xC000001D(ILLEGAL_INSTRUCTION=UBSan-trap). 非安全漏洞,仅导致sample_rate值未定义. Why: fuzzer构造的64位值重解释为double后超出int范围. How to apply: 防御性修复建议加范围检查(lrint或clamp). ASAN FFmpeg编译: clang64+compiler-rt, --cc=clang --enable-cross-compile --arch=x86_64 --target-os=mingw64.