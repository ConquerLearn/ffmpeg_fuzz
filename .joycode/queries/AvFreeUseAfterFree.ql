/**
 * @name FFmpeg: Use-after-free via av_free without pointer nullification
 * @description Detects av_free(p) without subsequent p=NULL, which may lead
 *              to use-after-free if p is accessed later.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cpp/ffmpeg-av-free-use-after-free
 * @tags security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.dataflow.TaintTracking

/** A call to av_free or av_freep */
class AvFreeCall extends FunctionCall {
  AvFreeCall() {
    this.getTarget().hasName("av_free") or
    this.getTarget().hasName("av_freep")
  }
}

/** Get the pointer variable being freed */
Expr getFreedPointer(AvFreeCall fc) {
  result = fc.getArgument(0)
}

/** An access to a variable that was previously freed */
predicate isAccessAfterFree(VariableAccess access, AvFreeCall freeCall) {
  exists(Variable v |
    // The free call frees variable v
    getFreedPointer(freeCall) = v.getAnAccess() and
    // The access is to the same variable
    access.getTarget() = v and
    // The access is after the free in the same function
    access.getEnclosingFunction() = freeCall.getEnclosingFunction() and
    // Basic control flow: access is reachable after free
    access.getBasicBlock().getASuccessor+() = freeCall.getBasicBlock() or
    freeCall.getBasicBlock().getASuccessor+() = access.getBasicBlock()
  )
}

from AvFreeCall freeCall, VariableAccess access
where isAccessAfterFree(access, freeCall)
select access, "Use-after-free: $@ was freed at $@ but accessed here without null check.",
  access.getTarget(), access.getTarget().getName(),
  freeCall, freeCall.toString()