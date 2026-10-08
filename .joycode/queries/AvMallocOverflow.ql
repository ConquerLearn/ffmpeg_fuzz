/**
 * @name FFmpeg: Integer overflow in av_malloc multiplication
 * @description Detects av_malloc(a * b) patterns where the multiplication
 *              may overflow, leading to undersized allocation and heap overflow.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id cpp/ffmpeg-av-malloc-overflow
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-680
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards

/** A call to av_malloc, av_mallocz, av_realloc, or av_calloc */
class AvAllocCall extends FunctionCall {
  AvAllocCall() {
    this.getTarget().hasName("av_malloc") or
    this.getTarget().hasName("av_mallocz") or
    this.getTarget().hasName("av_realloc") or
    this.getTarget().hasName("av_calloc")
  }
}

/** A multiplication expression that could overflow */
class PotentialOverflowMul extends MulExpr {
  PotentialOverflowMul() {
    // At least one operand is of type int or unsigned int (32-bit)
    exists(Type t |
      t = this.getLeftOperand().getType().getUnspecifiedType() or
      t = this.getRightOperand().getType().getUnspecifiedType() |
      t.getSize() = 4  // 32-bit type, overflow possible
    )
  }
}

from AvAllocCall alloc, PotentialOverflowMul mul
where mul = alloc.getArgument(0)
select alloc, "Potential integer overflow in $@: multiplication may overflow before allocation, use av_malloc_array instead.",
  mul, "allocation size"