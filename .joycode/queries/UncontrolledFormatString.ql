/**
 * @name FFmpeg: Uncontrolled format string
 * @description Detects printf-family functions where the format string
 *              may be controlled by user input, enabling arbitrary memory read/write.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id cpp/ffmpeg-uncontrolled-format-string
 * @tags security
 *       external/cwe/cwe-134
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

/** A printf-family function call */
class PrintfFamilyCall extends FunctionCall {
  PrintfFamilyCall() {
    this.getTarget().hasName("printf") or
    this.getTarget().hasName("fprintf") or
    this.getTarget().hasName("sprintf") or
    this.getTarget().hasName("snprintf") or
    this.getTarget().hasName("av_log") or
    this.getTarget().hasName("av_log_format_line") or
    this.getTarget().hasName("av_strerror")
  }
}

/** Get the format string argument for a printf-family call */
Expr getFormatArg(PrintfFamilyCall fc) {
  // For av_log(avcl, level, fmt, ...), format is arg 2
  fc.getTarget().hasName("av_log") and result = fc.getArgument(2)
  or
  // For fprintf(fp, fmt, ...), format is arg 1
  fc.getTarget().hasName("fprintf") and result = fc.getArgument(1)
  or
  // For snprintf(buf, size, fmt, ...), format is arg 2
  fc.getTarget().hasName("snprintf") and result = fc.getArgument(2)
  or
  // For printf/sprintf, format is arg 0
  (fc.getTarget().hasName("printf") or fc.getTarget().hasName("sprintf")) and
  result = fc.getArgument(0)
}

from PrintfFamilyCall fc, Expr fmt
where
  fmt = getFormatArg(fc) and
  not fmt instanceof StringLiteral
select fc, "Non-literal format string in $@: format string is not a constant, potential format string vulnerability.",
  fmt, "format argument"