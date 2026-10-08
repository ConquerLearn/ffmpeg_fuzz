---
name: clang-fuzzer-trace-pc-fix
description: Clang版fuzzer trace-pc无限递归修复记录
type: project
---

Clang版fuzzer崩溃根因与修复（2026-08-24）：

**根因**：standalone_driver.c被`-fsanitize-coverage=trace-pc`编译，导致编译器在`__sanitizer_cov_trace_pc()`回调函数内部也插入了trace-pc调用，形成无限递归→栈溢出(STATUS_STACK_OVERFLOW 0xC00000FD)。

**修复**：
1. standalone_driver.c：给所有coverage回调函数添加`__attribute__((no_sanitize("coverage")))`
2. build_clang_tracepc.sh：standalone_driver.c编译时使用DRIVER_CFLAGS（不含coverage标志）

**验证结果**：
- 单文件模式：coverage=460 edges（之前崩溃无法运行）
- Fuzzing模式：10秒89,603次运行，coverage增长到1,050 edges，语料库6→169

**Why**: trace-pc插桩会在每个控制流边插入`__sanitizer_cov_trace_pc()`调用，如果回调函数自身也被插桩，就会递归调用自身。

**How to apply**: 任何实现sanitizer回调的代码都不能被对应的sanitizer插桩，必须使用no_sanitize属性或单独编译。