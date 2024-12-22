import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

// gc_enter
// 

from 
  ValueVariable v,

  /*InnerPointerTakingFunctionCall pointerTakingCall,
  ControlFlowNode controlFlowNode, */
  GuardedPtr guardedPtr,
  VariableAccess guardedPtrAccess,
  DataFlow::Node vNode,
  DataFlow::Node guardedPtrNode,
  GcTriggerFunctionCall gcTriggerFunctionCall,
  Callable 
where
  vNode.asExpr() = v.getAnAccess() and
  guardedPtrAccess = guardedPtr.getAnAccess() and
  guardedPtrNode.asExpr() = guardedPtrAccess and
  DataFlow::localFlow(vNode, guardedPtrNode)
  and v.getInitializer().getASuccessor*() = gcTriggerFunctionCall
  and gcTriggerFunctionCall.getASuccessor*() = guardedPtrAccess
  // tripleTransition(v.getInitializer(), pointerTakingCall,  guardedPtrAccess)
select v,gcTriggerFunctionCall, guardedPtr