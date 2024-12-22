import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

from
  ValueVariable v, VariableAccess pointerAccess, DataFlow::Node source, DataFlow::Node sink
where
  // v.getAnAccess() = pointerAccess and
  // pointerAccess = v.getInitializer().getASuccessor+() and

  // isInnerPointerTaken(v, pointerAccess)
  source.asExpr() = v.getAnAccess() and sink.asExpr() = pointerAccess
  and pointerAccess.getTarget().getType().getName().matches("")
  and InnerPointerFlow::flow(source, sink)
select v, pointerAccess, "Inner pointer potentially used after GC trigger without proper guard"