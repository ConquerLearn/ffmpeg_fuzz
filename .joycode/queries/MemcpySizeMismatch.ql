/**
 * @name FFmpeg: memcpy with mismatched source/destination size
 * @description Detects memcpy/memmove where the copy size may exceed the
 *              destination buffer size, causing heap/stack buffer overflow.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id cpp/ffmpeg-memcpy-size-mismatch
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-787
 */

import cpp

/** A call to memcpy or memmove */
class MemcpyCall extends FunctionCall {
  MemcpyCall() {
    this.getTarget().hasName("memcpy") or
    this.getTarget().hasName("memmove") or
    this.getTarget().hasName("av_memcpy_backptr")
  }
}

/** A variable-length array or malloc'd buffer used as memcpy destination */
predicate isDynamicDest(MemcpyCall mc, Expr dest) {
  dest = mc.getArgument(0) and
  (
    // Destination is a pointer from malloc/av_malloc
    dest.getType().getUnspecifiedType() instanceof PointerType or
    // Destination is an array with variable index
    exists(ArrayExpr ae | ae = dest)
  )
}

from MemcpyCall mc
where
  // Size argument is not a compile-time constant
  not mc.getArgument(2).getValue().regexpMatch("\\d+")
select mc, "memcpy/memmove with non-constant size $@: verify destination buffer is large enough.",
  mc.getArgument(2), "copy size"