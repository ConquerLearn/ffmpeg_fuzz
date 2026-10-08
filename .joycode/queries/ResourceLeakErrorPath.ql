/**
 * @name FFmpeg: Resource leak on error path
 * @description Detects error return paths (goto error label) where allocated
 *              resources are not freed, causing memory/file descriptor leaks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id cpp/ffmpeg-resource-leak-error-path
 * @tags security
 *       external/cwe/cwe-401
 *       external/cwe/cwe-772
 */

import cpp

/** An av_malloc/av_mallocz allocation call */
class AllocCall extends FunctionCall {
  AllocCall() {
    this.getTarget().hasName("av_malloc") or
    this.getTarget().hasName("av_mallocz") or
    this.getTarget().hasName("av_malloc_array") or
    this.getTarget().hasName("av_calloc") or
    this.getTarget().hasName("av_realloc")
  }
}

/** A free call */
class FreeCallInline extends FunctionCall {
  FreeCallInline() {
    this.getTarget().hasName("av_free") or
    this.getTarget().hasName("av_freep") or
    this.getTarget().hasName("av_frame_free") or
    this.getTarget().hasName("av_packet_free")
  }
}

/** A goto statement targeting an error-like label */
class GotoError extends GotoStmt {
  GotoError() {
    // Match goto targets whose target statement text contains "error" or "fail"
    this.getTarget().toString().toLowerCase().regexpMatch(".*error.*|.*fail.*|.*cleanup.*")
  }
}

from AllocCall alloc, GotoError gotoErr, Variable v
where
  // Allocation result is stored in variable v
  alloc = v.getAnAssignedValue() and
  // There's a goto error in the same function
  gotoErr.getEnclosingFunction() = alloc.getEnclosingFunction() and
  // The goto comes after the allocation
  gotoErr.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
  // Variable v is not freed before the goto (simplified check)
  not exists(FreeCallInline fc |
    fc.getEnclosingFunction() = alloc.getEnclosingFunction() and
    fc.getArgument(0) = v.getAnAccess() and
    fc.getLocation().getStartLine() > alloc.getLocation().getStartLine() and
    fc.getLocation().getStartLine() < gotoErr.getLocation().getStartLine()
  )
select gotoErr, "Potential resource leak: $@ allocated at $@ may not be freed before this goto.",
  v, v.getName(),
  alloc, "allocation"