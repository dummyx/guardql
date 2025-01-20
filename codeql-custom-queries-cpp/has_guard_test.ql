import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

from 
  ValueVariable v, GuardedPtr gP, DataFlow::Node source, DataFlow::Node sink
where
  source.asVariable() = v
  and sink.asVariable() = gP
  and DataFlow::localFlow(source, sink)

select v, gP, "Inner pointer potentially used after GC trigger without proper guard"