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
  Initializer vInit,

  GuardedPtr guardedPtr,
  VariableAccess guardedPtrAccess,
  DataFlow::Node vNode,
  DataFlow::Node guardedPtrNode,
  DataFlow::Node pointerNode,
  DataFlow::Node gcTriggerNode,

  InnerPointerTakingFunctionCallByType innerPtrTakingCall,

  GcTriggerCall gcTriggerCall,
  VariableAccess pointerInitAccess,
  VariableAccess pointerUsageAccess,
  Assignment pointerAssignment
where

  pointerInitAccess = innerPtrTakingCall.getAnArgument() or (
    pointerAssignment.getLValue() = pointerInitAccess and
    pointerAssignment.getRValue() = innerPtrTakingCall
  ) 

select pointerInitAccess