import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph
import guard_checker

from ValueVariable v
where
  isNeedGuard(v) and not isProperlyGuarded(v)
select v