# FFmpeg 8.1 二进制漏洞专项审计报告

审计日期：2026-08-20
审计对象：C:\Users\Administrator\Desktop\1\8-6\FFmpeg-release-8.1（FFmpeg 8.1 源码树）
审计方法：CodeQL 2.25.5 + cpp-queries 1.6.3 定向内存安全查询套件（46 个查询），
数据库基线 1,384,557 行 C/C++，对 `.codeql-db`（已 finalize 的全量数据库）分析。
结果文件：`ffmpeg-memcorr.sarif`（532 条结果，44 条规则）

## 1. 结论摘要

| 类别 | 结果 |
| --- | --- |
| use-after-free | 0 条（无 CodeQL 可确认路径） |
| double-free | 0 条 |
| 越界写（overrun-write 系列，error 级） | 0 条 |
| 越界读（invalid-pointer-deref / overflow-buffer） | 1 条（已人工排除，见 §4） |
| 未初始化变量（uninitialized-local） | 1 条真实缺陷（mov.c，见 §2.1） |
| 条件性未初始化 | 24 条，其中 2 条真实（rka.c、opus/enc.c，见 §2.2-2.3） |
| 污点整数溢出 | 71 条，多数为低危；1 条值得关注（dvdsubdec.c，见 §2.4） |
| 空指针解引用（missing-null-test） | 206 条（note 级，多数为 av_malloc 模式误报） |
| 栈地址逃逸 | 12 条，均经人工验证为同步使用模式，非漏洞 |

**总体判断：该 8.1 源码树未发现 CodeQL 可确认的可直接利用的
内存破坏漏洞（UAF / 双重释放 / 缓冲区越界写）。**
发现 3 个真实但低危的缺陷和 1 个值得关注的污点溢出点，建议修复。

## 2. 真实缺陷（建议修复）

### 2.1 [中] mov_read_chnl 返回未初始化变量

位置：`libavformat/mov.c:1230,1253`

`mov_read_chnl()` 声明 `int ret;` 后调用 `ff_mov_read_chnl()` 未保存返回值，
最后直接 `return ret;`（CodeQL: cpp/uninitialized-local, sev=7.8）。
含 `chnl` box 的 MOV/MP4 输入可到达该路径。

影响：未定义返回值可能把成功解析误判为错误，或吞掉真实解析错误；
当前无证据表明可直接造成内存破坏，但属真实、可修复的解析器缺陷。

修复建议：

```c
ret = ff_mov_read_chnl(c->fc, pb, st);
if (ret < 0)
    return ret;
```

### 2.2 [中] RKA 解码器条件性未初始化读取

位置：`libavcodec/rka.c:464,471`（CodeQL: cpp/conditionally-uninitialized-variable）

`ac_get_freq()` 在 `freq == 0` 或 `new_high == 0` 时返回 -1 且**不写** `*result`。
`amdl_decode_int()` 在 `am->total == am->buf_size` 时以 `freq = am->buf_size - am->total = 0`
调用 `ac_get_freq()`，且不检查返回值，随后 `if (val > 0 ...)` 读取未初始化 `val`。

影响：恶意 RKA 音频流可触发未初始化读取（UB）。`dst[0]` 后续仍受 `size` 限制，
越界访问概率低，但属解码器输入可控的未初始化读，应修复。

修复建议：

```c
if (ac_get_freq(ac, am->buf_size - am->total, &val) < 0)
    return AVERROR_INVALIDDATA;
```

（另一个调用点 `ac_get_freq(ac, freq, &val)` 同样需要检查返回值。）

### 2.3 [低] opus_packet_assembler 条件性未初始化 offset

位置：`libavcodec/opus/enc.c:502`（CodeQL: cpp/conditionally-uninitialized-variable）

`opus_gen_toc()` 在配置组合非法（`cfg == 0`）时返回 1 且**不写** `*size`；
`opus_packet_assembler()` 不检查返回值，直接使用 `offset` 计算
`avpkt->size`。触发依赖编码器内部状态，为低概率路径，但属真实缺陷。

修复建议：`opus_gen_toc()` 在 `if (!cfg)` 分支先写 `*size = 0;`，
或调用方检查返回值。

### 2.4 [低-中] DVD subtitle IFO 解析 32 位整数溢出（污点）

位置：`libavcodec/dvdsubdec.c:605-606`（CodeQL: cpp/tainted-arithmetic, sev=8.6）

`pgci = av_be2ne32(sp_pgci) * 2048` 与 `pgc = pgci + av_be2ne32(off_pgc)`
均为 32 位无符号运算，两个乘数/加数直接来自用户提供的 IFO 文件。
溢出后 `fseek()` 定位到任意偏移，仅读取 64 字节到栈上 `yuv[65]`，
**不会造成内存越界**；影响限于错误解析调色板。属稳健性缺陷，
在解析含恶意偏移的 IFO 文件时应做溢出保护（改用 64 位中间量并校验范围）。

## 3. 需注意但风险较低的模式

1. `av_pix_fmt_get_chroma_sub_sample()` 返回值未检查
   （h264_slice.c:229、lcldec.c:556、mjpegdec.c:1472 等 9 处）：
   该函数对合法 pixel format 恒返回 0，仅对非法枚举返回负值；
   由于调用处 format 均来自已校验的帧，实际不可达。建议仍加检查。
2. `avpriv_mpeg4audio_get_config2()` 返回值未检查
   （mpegaudiodec_template.c:1760）：调用前已保证 extradata ≥ 2 字节，
   失败路径概率极低。
3. `av_opt_get_int()` / `av_chroma_location_enum_to_pos()` 返回值未检查
   （af_aresample.c、af_loudnorm.c、matroskaenc.c:1402、swscale/graph.c:321 等）：
   同属"已知 API 在合法参数下恒成功"模式。
4. missing-null-test 206 条：绝大多数是 `av_malloc` 系列返回值
   （FFmpeg 默认分配失败即 abort），以及 `av_packet_alloc`/`av_frame_alloc`
   后未判空；属 FFmpeg 全局约定，非实际可利用路径。个别点
   （如 `libavformat/concatdec.c:559-624`、`movenc.c:3232-3248`）为
   `avformat_new_stream` 返回值使用，同样受 FFmpeg 约定保护。
5. suspicious-call-to-memset 9 条（ac3enc、h264addpx、h264pred 模板）：
   模板宏按类型 sizeof 清数组，属 DSP 模板惯用法，误报。
6. incorrect-pointer-scaling-char 112 条：`(uint8_t*)ptr + n` 在
   DSP/编解码模板中的显式字节寻址，CodeQL 对强制转换后的指针运算误报。
7. stack-address-escape 12 条：均经人工验证为**同步使用**模式——
   zlib `next_in` 指向局部 `header`/`start`（flashsv.c:182、mscc.c:162）、
   `mov->pkt->data` 指向局部 `data[2]`（movenc.c:7273,7642）、
   `s->buf = &ptr`（tiffenc.c:343）等，均在函数返回前完成使用或复位。
8. dovi_rpuenc.c:299 `memcmp` 溢出告警（sev=9.3）：
   `memcmp(&dm1->signal_eotf, &dm2->signal_eotf, sizeof(AVDOVIColorMetadata)
   - offsetof(..., signal_eotf))`，两个实参都是完整结构体，比较范围
   未超出对象末尾——CodeQL 误将成员后的可用空间判为 22 字节。误报。
9. libavutil/mem.c:308 `av_memdup` 分配大小不受控（sev=8.1）：
   通用 API，大小由调用方传入，CodeQL 将调用点污点传播归因到 API 实现。
   需在具体调用点评估（本库中未发现高危调用点）。误报。

## 4. 已知 CVE 关联说明

官方公告中 8.1.2 已包含 CVE-2026-8461 与 CVE-2026-30999 修复。
本次扫描未发现与这两项同类（UAF/越界写）的残留模式。
静态扫描结论不能替代 ASan/UBSan 模糊测试。

## 5. 局限

1. 数据库构建于禁用 programs、avdevice、network 和 x86 汇编的配置，
   约 1,536 个平台相关/未启用文件未纳入分析。
2. CodeQL 对模板宏、强制类型转换、FFmpeg 分配约定存在系统性误报，
   本次已人工复核全部 high-severity 项。
3. 未做动态验证（fuzzing）；建议对 rka、dvdsubdec、mov chnl 路径
   补充 ASan 模糊测试。

## 6. 修复优先级建议

1. 立即：`mov.c` 未初始化 `ret`（§2.1）——改动 2 行，消除 UB。
2. 尽快：`rka.c` 返回值检查（§2.2）——解码器输入可控。
3. 择机：`opus/enc.c`（§2.3）、`dvdsubdec.c` 溢出保护（§2.4）。
4. 可选：统一补充 `av_pix_fmt_get_chroma_sub_sample` 等 API 返回值检查。
