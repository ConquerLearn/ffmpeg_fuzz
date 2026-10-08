/**
 * @name FFmpeg: AVBufferRef ref/unref imbalance
 * @description Detects av_buffer_ref() calls without corresponding
 *              av_buffer_unref() in the same function, which may cause
 *              reference count leaks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id cpp/ffmpeg-avbuffer-ref-unref-imbalance
 * @tags security
 *       external/cwe/cwe-401
 */
import cpp

class AVBufferRefCall extends FunctionCall {
  AVBufferRefCall() {
    this.getTarget().hasName("av_buffer_ref") or
    this.getTarget().hasName("av_buffer_alloc") or
    this.getTarget().hasName("av_buffer_create") or
    this.getTarget().hasName("av_buffer_make_writable")
  }
}

class AVBufferUnrefCall extends FunctionCall {
  AVBufferUnrefCall() {
    this.getTarget().hasName("av_buffer_unref")
  }
}

from AVBufferRefCall refCall, Variable v
where
  // v is assigned the ref result
  v.getAnAssignedValue() = refCall and
  refCall.getEnclosingFunction() = v.getAnAccess().getEnclosingFunction() and
  // v's type involves AVBufferRef
  v.getType().getUnspecifiedType().toString().regexpMatch(".*AVBufferRef.*") and
  // No unref of v in the same function
  not exists(AVBufferUnrefCall unref |
    unref.getAnArgument().toString().regexpMatch(".*" + v.getName() + ".*") and
    unref.getEnclosingFunction() = refCall.getEnclosingFunction()
  ) and
  // v is not returned (ownership transferred to caller)
  not exists(ReturnStmt ret |
    ret.getExpr().getAChild*() = v.getAnAccess() and
    ret.getEnclosingFunction() = refCall.getEnclosingFunction()
  )
select refCall, "Potential AVBufferRef leak: $@ is ref'd/allocated but may not be unref'd in this function.",
  v, v.getName()