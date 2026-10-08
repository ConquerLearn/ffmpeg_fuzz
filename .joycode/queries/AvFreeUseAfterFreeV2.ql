/**
 * @name FFmpeg: Use-after-free via av_free without pointer nullification (v2)
 * @description Detects av_free(p) where p is NOT set to NULL afterwards and
 *              p is dereferenced (not just passed to another free) on a reachable path.
 *              Excludes av_freep (which nullifies) and cases with null guards.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/ffmpeg-av-free-use-after-free-v2
 * @tags security
 *       external/cwe/cwe-416
 */
import cpp

/** A call to av_free (NOT av_freep, which nullifies the pointer) */
class AvFreeOnlyCall extends FunctionCall {
  AvFreeOnlyCall() {
    this.getTarget().hasName("av_free")
  }
}

from AvFreeOnlyCall freeCall, VariableAccess deref, Variable v
where
  // The free call frees variable v (direct access, not &v)
  freeCall.getArgument(0) = v.getAnAccess() and
  // deref is an access to v that is a dereference (p->field, p[i], or *p)
  deref.getTarget() = v and
  (deref.getParent() instanceof FieldAccess or
   deref.getParent() instanceof ArrayExpr or
   deref.getParent() instanceof PointerDereferenceExpr) and
  // Same function
  deref.getEnclosingFunction() = freeCall.getEnclosingFunction() and
  // Dereference is after free in source order
  deref.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
  // No nullification of v between free and deref
  not exists(AssignExpr assign |
    assign.getLValue() = v.getAnAccess() and
    (assign.getRValue().toString() = "NULL" or assign.getRValue().toString() = "0" or assign.getRValue().toString() = "nullptr") and
    assign.getEnclosingFunction() = freeCall.getEnclosingFunction() and
    assign.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
    assign.getLocation().getStartLine() < deref.getLocation().getStartLine()
  ) and
  // No av_freep on v between free and deref
  not exists(FunctionCall fc |
    fc.getTarget().hasName("av_freep") and
    fc.getArgument(0).toString().regexpMatch("&.*" + v.getName() + ".*") and
    fc.getEnclosingFunction() = freeCall.getEnclosingFunction() and
    fc.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
    fc.getLocation().getStartLine() < deref.getLocation().getStartLine()
  ) and
  // Not passing to another free function
  not exists(FunctionCall fc |
    fc.getAnArgument() = deref and
    (fc.getTarget().hasName("av_free") or fc.getTarget().hasName("free"))
  )
select deref, "Potential use-after-free: $@ was freed at $@ and dereferenced here without nullification.",
  v, v.getName(),
  freeCall, "av_free"