/**
 * @name FFmpeg: Tainted array index
 * @description User-controlled data flowing to array index expressions
 *              could lead to out-of-bounds access.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cpp/ffmpeg-tainted-array-index
 * @tags security
 *       external/cwe/cwe-129
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import TaintedArrayIndex::PathGraph

/**
 * An array index expression where user-controlled data could cause OOB access.
 */
predicate arrayIndexSink(ArrayExpr arr, DataFlow::Node sink) {
  exists(Expr e | e = sink.asExpr() |
    e = arr.getArrayOffset() and
    e.getUnspecifiedType() instanceof IntegralType
  )
}

predicate isFlowSource(FlowSource source, string sourceType) {
  sourceType = source.getSourceType()
}

module TaintedArrayIndexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isFlowSource(source, _) }

  predicate isSink(DataFlow::Node sink) { arrayIndexSink(_, sink) }

  predicate isBarrier(DataFlow::Node node) {
    exists(Expr e | e = node.asExpr() |
      // Simple bounds check: comparison with a constant
      exists(RelationalOperation oper |
        oper.getAnOperand() = e and
        not oper.getAnOperand().getValue() = "0"
      )
    )
  }
}

module TaintedArrayIndex = TaintTracking::Global<TaintedArrayIndexConfig>;

from
  ArrayExpr arr, TaintedArrayIndex::PathNode source,
  TaintedArrayIndex::PathNode sink, string taintCause
where
  isFlowSource(source.getNode(), taintCause) and
  TaintedArrayIndex::flowPath(source, sink) and
  arrayIndexSink(arr, sink.getNode())
select arr, source, sink,
  "This array index is derived from $@ and could lead to out-of-bounds access.",
  source.getNode(), "user input (" + taintCause + ")"