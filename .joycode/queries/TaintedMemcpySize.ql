/**
 * @name FFmpeg: Tainted memcpy size
 * @description User-controlled data flowing to memcpy/memmove size arguments
 *              could lead to buffer overflow.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id cpp/ffmpeg-tainted-memcpy-size
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import TaintedMemcpySize::PathGraph

/**
 * A memcpy/memmove/av_memcpy call.
 */
class MemcpyLikeCall extends FunctionCall {
  MemcpyLikeCall() {
    this.getTarget().hasName("memcpy") or
    this.getTarget().hasName("memmove") or
    this.getTarget().hasName("av_memcpy_backptr")
  }
}

/**
 * Holds if `call` is a memcpy-like call, and `tainted` is the size argument.
 */
predicate memcpySink(MemcpyLikeCall call, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    // Size argument is typically the 3rd argument (index 2)
    e = call.getArgument(2) and
    e.getUnspecifiedType() instanceof IntegralType
  )
}

predicate isFlowSource(FlowSource source, string sourceType) {
  sourceType = source.getSourceType()
}

module TaintedMemcpySizeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFlowSource(source, _) }

  predicate isSink(DataFlow::Node sink) { memcpySink(_, sink) }

  predicate isBarrier(DataFlow::Node node) {
    exists(Expr e | e = node.asExpr() |
      // Simple bounds check: comparison with a constant
      exists(RelationalOperation oper |
        oper.getAnOperand() = e and
        not oper.getAnOperand().getValue() = "0"
      )
    )
    or
    // Block flow into memcpy functions to avoid duplicate results
    any(MemcpyLikeCall f).getTarget().getAParameter() = node.asParameter()
  }
}

module TaintedMemcpySize = TaintTracking::Global<TaintedMemcpySizeConfig>;

from
  MemcpyLikeCall call, TaintedMemcpySize::PathNode source,
  TaintedMemcpySize::PathNode sink, string taintCause
where
  isFlowSource(source.getNode(), taintCause) and
  TaintedMemcpySize::flowPath(source, sink) and
  memcpySink(call, sink.getNode())
select call, source, sink,
  "This memcpy size is derived from $@ and could lead to buffer overflow.",
  source.getNode(), "user input (" + taintCause + ")"