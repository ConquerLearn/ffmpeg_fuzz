/**
 * @name FFmpeg: Resource leak on error path (v2)
 * @description Detects allocated resources that may leak when a function
 *              returns early on error paths. Looks for av_malloc followed by
 *              return/goto without corresponding av_free in between.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cpp/ffmpeg-resource-leak-error-path-v2
 * @tags security
 *       external/cwe/cwe-401
 *       external/cwe/cwe-772
 */
import cpp

class AvAllocCall extends FunctionCall {
  AvAllocCall() {
    this.getTarget().hasName("av_malloc") or
    this.getTarget().hasName("av_mallocz") or
    this.getTarget().hasName("av_malloc_array") or
    this.getTarget().hasName("av_calloc") or
    this.getTarget().hasName("av_realloc") or
    this.getTarget().hasName("av_realloc_array")
  }
}

class AvFreeCall extends FunctionCall {
  AvFreeCall() {
    this.getTarget().hasName("av_free") or
    this.getTarget().hasName("av_freep") or
    this.getTarget().hasName("av_frame_free") or
    this.getTarget().hasName("av_packet_free")
  }
}

from AvAllocCall alloc, Variable v, Stmt earlyExit
where
  // v is assigned the allocation result
  v.getAnAssignedValue() = alloc and
  alloc.getEnclosingFunction() = v.getAnAccess().getEnclosingFunction() and
  // earlyExit is a return or goto after the allocation
  (earlyExit instanceof ReturnStmt or earlyExit instanceof GotoStmt) and
  earlyExit.getEnclosingFunction() = alloc.getEnclosingFunction() and
  earlyExit.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
  // No free of v between alloc and earlyExit
  not exists(AvFreeCall fc |
    fc.getArgument(0) = v.getAnAccess() and
    fc.getEnclosingFunction() = alloc.getEnclosingFunction() and
    fc.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    fc.getLocation().getStartLine() <= earlyExit.getLocation().getStartLine()
  ) and
  // No reassignment of v between alloc and earlyExit (means ownership transferred)
  not exists(AssignExpr assign |
    assign.getLValue() = v.getAnAccess() and
    assign.getEnclosingFunction() = alloc.getEnclosingFunction() and
    assign.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    assign.getLocation().getStartLine() <= earlyExit.getLocation().getStartLine()
  ) and
  // v is not returned (ownership not transferred to caller)
  not exists(ReturnStmt ret |
    ret.getExpr().getAChild*() = v.getAnAccess() and
    ret.getEnclosingFunction() = alloc.getEnclosingFunction()
  )
select earlyExit, "Potential resource leak: $@ allocated at $@ may not be freed before this exit point.",
  v, v.getName(),
  alloc, "allocation"