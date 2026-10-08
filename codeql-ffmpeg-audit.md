# FFmpeg 8.1.2 CodeQL 全库安全扫描报告

扫描日期：2026-08-13

## 范围与方法

- 源码版本：FFmpeg 8.1.2
- CodeQL CLI：2.25.5
- 查询套件：`cpp-security-and-quality.qls`
- 数据库基线：1,384,557 行 C/C++
- 本次查询覆盖：4,561 个 C/C++ 文件中的 3,025 个
- 原始结果：`codeql-ffmpeg-full.sarif`

官方 FFmpeg 安全公告显示，8.1.2 已包含 CVE-2026-8461 与
CVE-2026-30999 的修复。本次扫描用于确认当前代码中的同类缺陷模式，
不能仅凭静态告警认定新的 CVE。

## 结果摘要

- 总告警：4,330
- 带 CodeQL security-severity 的告警：778
- 其中 625 条为宽类型转换前的乘法告警，多数受 FFmpeg 尺寸约束保护
- 未发现 CodeQL 可确认的 use-after-free、double-free、污点越界写或命令注入路径

## 值得修复的问题

### 1. MOV `chnl` 解析函数返回未初始化变量

位置：`libavformat/mov.c:1230,1253`

`mov_read_chnl()` 声明 `int ret`，调用 `ff_mov_read_chnl()` 时没有保存其返回值，
最后直接 `return ret`。包含 `chnl` box 的输入可到达该路径。

影响：未定义返回值可能把成功解析误判成错误，或者吞掉真实解析错误。
目前没有证据表明它可以直接造成内存破坏，但这是可信、可修复的解析器缺陷。

建议：

```c
ret = ff_mov_read_chnl(c->fc, pb, st);
if (ret < 0)
    return ret;
```

### 2. JPEG 2000 tile-part 长度小于 9 时发生无符号下溢

位置：`libavcodec/jpeg2000_parser.c:125`

表达式中的值是 `uint32_t`：

```c
(state64 & 0xFFFFFFFF) - 9 > 0
```

当字段值为 0..8 时，减法先无符号下溢，条件仍为真，`skip_bytes` 被设置成
接近 `UINT32_MAX` 的值，而不是 0。

影响：解析器可能长时间跳过后续输入并造成错误分帧；当前没有发现越界写路径。
对流式或持续输入场景应进一步做超时/资源消耗测试。

建议先比较再减：

```c
uint32_t len = state64 & 0xFFFFFFFF;
m->skip_bytes = len > 9 ? len - 9 : 0;
```

## 已人工排除的高分告警

- `libavcodec/dovi_rpuenc.c:299`：`memcmp` 从结构体成员一直比较到结构体末尾，
  两个参数都指向完整的 `AVDOVIColorMetadata` 对象；CodeQL 将成员后的可用空间
  误判为仅 22 字节。
- `libavcodec/bmp.c:185,192`：此前已经验证 `ihsize + 14 <= hsize`，因此这里的
  无符号减法不会下溢。
- `libavcodec/h264idct_template.c`、`h264pred_template.c` 的 pointer scaling：模板用
  `sizeof(pixel)` 表示按像素大小选择固定偏移，属于模板宏造成的误报。
- `libavcodec/aacps.c`、`aacsbr*.c` 的 pointer scaling：多维数组强制转换是 DSP
  数据布局的一部分，告警未形成越界路径。
- `libavutil/mem.c:308`：`av_memdup()` 是通用内存 API，大小由调用方提供；CodeQL
  把某个调用路径的输入传播归到 API 实现本身。资源限制需在具体调用点判断。
- 下标检查顺序的 6 条告警均受数组额外终止槽、循环不变量或短路求值保护。

## 局限

当前数据库是在禁用 programs、avdevice、network 和 x86 汇编的配置下构建的，
没有覆盖 1,536 个平台相关、未启用或未参与该构建的 C/C++ 文件。静态扫描结果
不能替代 ASan/UBSan 模糊测试，也不能证明代码不存在漏洞。
