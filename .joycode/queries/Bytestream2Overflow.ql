/**
 * @name FFmpeg: bytestream2 buffer overread
 * @description Detects bytestream2_get_buffer calls where the requested size
 *              may exceed the remaining buffer, causing out-of-bounds read.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/ffmpeg-bytestream2-overread
 * @tags security
 *       external/cwe/cwe-119
 */

import cpp

/** A call to bytestream2_get_buffer or bytestream2_get_bufferu */
class Bytestream2GetBufferCall extends FunctionCall {
  Bytestream2GetBufferCall() {
    this.getTarget().hasName("bytestream2_get_buffer") or
    this.getTarget().hasName("bytestream2_get_bufferu") or
    this.getTarget().hasName("bytestream2_get_bufferu8")
  }
}

/** A call to bytestream2_init where buffer size is set */
class Bytestream2InitCall extends FunctionCall {
  Bytestream2InitCall() {
    this.getTarget().hasName("bytestream2_init") or
    this.getTarget().hasName("bytestream2_init_reader") or
    this.getTarget().hasName("bytestream2_init_writer")
  }
}

from Bytestream2GetBufferCall call
where
  // Size argument is not a constant
  not call.getArgument(1).getValue().regexpMatch("\\d+")
select call, "bytestream2_get_buffer with non-constant size $@: may overread buffer if size exceeds remaining bytes.",
  call.getArgument(1), "size"