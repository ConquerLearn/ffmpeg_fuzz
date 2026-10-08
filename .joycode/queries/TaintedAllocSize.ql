/**
 * @name FFmpeg: Tainted allocation size
 * @description User-controlled data flowing to FFmpeg allocation size arguments
 *              could lead to arbitrary memory allocation or integer overflow.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id cpp/ffmpeg-tainted-alloc-size
 * @tags security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-789
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import TaintedAllocSize::PathGraph

/**
 * An FFmpeg allocation function call.
 */
class FfmpegAllocCall extends FunctionCall {
  FfmpegAllocCall() {
    this.getTarget().hasName("av_malloc") or
    this.getTarget().hasName("av_mallocz") or
    this.getTarget().hasName("av_malloc_array") or
    this.getTarget().hasName("av_calloc") or
    this.getTarget().hasName("av_realloc") or
    this.getTarget().hasName("av_realloc_array")
  }
}

/**
 * Holds if `alloc` is an FFmpeg allocation, and `tainted` is a child of it
 * that is a taint sink.
 */
predicate ffmpegAllocSink(FfmpegAllocCall alloc, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    e = alloc.getAnArgument() and
    e.getUnspecifiedType() instanceof IntegralType
  )
}

predicate isFlowSource(FlowSource source, string sourceType) {
  sourceType = source.getSourceType()
}

module TaintedAllocSizeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFlowSource(source, _) }

  predicate isSink(DataFlow::Node sink) { ffmpegAllocSink(_, sink) }

  predicate isBarrier(DataFlow::Node node) {
    exists(Expr e | e = node.asExpr() |
      // Simple bounds check: comparison with a constant
      exists(RelationalOperation oper |
        oper.getAnOperand() = e and
        not oper.getAnOperand().getValue() = "0"
      )
    )
    or
    // Block flow into allocation functions to avoid duplicate results
    any(FfmpegAllocCall f).getTarget().getAParameter() = node.asParameter()
  }
}

module TaintedAllocSize = TaintTracking::Global<TaintedAllocSizeConfig>;

from
  FfmpegAllocCall alloc, TaintedAllocSize::PathNode source,
  TaintedAllocSize::PathNode sink, string taintCause
where
  isFlowSource(source.getNode(), taintCause) and
  TaintedAllocSize::flowPath(source, sink) and
  ffmpegAllocSink(alloc, sink.getNode())
select alloc, source, sink,
  "This FFmpeg allocation size is derived from $@ and could allocate arbitrary amounts of memory.",
  source.getNode(), "user input (" + taintCause + ")"