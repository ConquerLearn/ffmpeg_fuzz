/**
 * @name FFmpeg: AVPacket resource leak
 * @description Detects AVPacket variables that are initialized (av_init_packet,
 *              av_packet_alloc, av_packet_ref) but never freed (av_packet_free,
 *              av_packet_unref) in the same function scope.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id cpp/ffmpeg-avpacket-leak
 * @tags security
 *       external/cwe/cwe-401
 */
import cpp

class AVPacketAllocCall extends FunctionCall {
  AVPacketAllocCall() {
    this.getTarget().hasName("av_packet_alloc") or
    this.getTarget().hasName("av_packet_clone") or
    this.getTarget().hasName("av_packet_ref") or
    this.getTarget().hasName("av_init_packet")
  }
}

class AVPacketFreeCall extends FunctionCall {
  AVPacketFreeCall() {
    this.getTarget().hasName("av_packet_free") or
    this.getTarget().hasName("av_packet_unref") or
    this.getTarget().hasName("av_packet_move_ref")
  }
}

from AVPacketAllocCall alloc, Variable v
where
  // v is assigned the allocation result
  v.getAnAssignedValue() = alloc and
  alloc.getEnclosingFunction() = v.getAnAccess().getEnclosingFunction() and
  // v's type is AVPacket* or AVPacket
  v.getType().getUnspecifiedType().toString().regexpMatch("AVPacket\\*?") and
  // No free of v in the same function
  not exists(AVPacketFreeCall fc |
    fc.getAnArgument().toString().regexpMatch(".*" + v.getName() + ".*") and
    fc.getEnclosingFunction() = alloc.getEnclosingFunction()
  ) and
  // v is not returned (ownership transferred)
  not exists(ReturnStmt ret |
    ret.getExpr().getAChild*() = v.getAnAccess() and
    ret.getEnclosingFunction() = alloc.getEnclosingFunction()
  ) and
  // v is not passed to a function that takes ownership
  not exists(FunctionCall fc |
    fc.getAnArgument() = v.getAnAccess() and
    (fc.getTarget().hasName("av_write_frame") or
     fc.getTarget().hasName("av_write_trailer") or
     fc.getTarget().hasName("av_interleaved_write_frame") or
     fc.getTarget().hasName("avcodec_send_packet"))
  )
select alloc, "Potential AVPacket leak: $@ is allocated but may not be freed in this function.",
  v, v.getName()