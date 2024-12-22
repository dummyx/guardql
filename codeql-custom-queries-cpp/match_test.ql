import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

from 

  /*InnerPointerTakingFunctionCall pointerTakingCall,
  ControlFlowNode controlFlowNode, */
  GcTriggerFunctionCall gcTriggerFunctionCall
where
1=1
select gcTriggerFunctionCall