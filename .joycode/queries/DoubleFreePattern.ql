/**
 * @name FFmpeg: Double free pattern
 * @description Detects potential double-free where the same pointer is freed
 *              more than once along the same execution path.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id cpp/ffmpeg-double-free
 * @tags security
 *       external/cwe/cwe-415
 */

import cpp
import semmle.code.cpp.controlflow.Guards

/** A call to av_free, av_freep, av_free_packet, or av_frame_free */
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasName("av_free") or
    this.getTarget().hasName("av_freep") or
    this.getTarget().hasName("av_free_packet") or
    this.getTarget().hasName("av_frame_free") or
    this.getTarget().hasName("av_packet_free") or
    this.getTarget().hasName("av_packet_unref") or
    this.getTarget().hasName("ff_free_packet")
  }
}

from FreeCall free1, FreeCall free2, Variable v
where
  // Both free calls target the same variable
  free1.getArgument(0) = v.getAnAccess() and
  free2.getArgument(0) = v.getAnAccess() and
  free1 != free2 and
  // Same function
  free1.getEnclosingFunction() = free2.getEnclosingFunction() and
  // free1 comes before free2 in the function
  free1.getLocation().getStartLine() < free2.getLocation().getStartLine()
select free2, "Potential double-free: $@ is freed again here after being freed at $@.",
  v, v.getName(),
  free1, "first free"