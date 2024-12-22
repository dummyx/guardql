import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

from 
  ValueVariable v 
where
  hasGuard(v)

select v, "Inner pointer potentially used after GC trigger without proper guard"