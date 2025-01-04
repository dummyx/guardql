

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
  VariableAccess vAccess,

  GuardedPtr guardedPtr,
  VariableAccess guardedPtrAccess,
  DataFlow::Node vNode,
  DataFlow::Node guardedPtrNode,
  DataFlow::Node pointerNode,

  InnerPointerTakingFunctionCallByType innerPtrTakingCall,

  GcTriggerCall gcTriggerCall,
  VariableAccess pointerInitAccess,
  VariableAccess pointerUsageAccess,
  Assignment pointerAssignment
where

  vAccess = v.getAnAccess() and
  vNode.asExpr() = vAccess and

  
  guardedPtrAccess = guardedPtr.getAnAccess() and
  guardedPtrNode.asExpr() = guardedPtrAccess and

  pointerInitAccess = innerPtrTakingCall.getAnArgument() or (
    pointerAssignment.getLValue() = pointerInitAccess and
    pointerAssignment.getRValue() = innerPtrTakingCall
  )  and

  pointerNode.asExpr() = pointerUsageAccess and

  DataFlow::localFlow(vNode, pointerNode) and
  
  innerPtrTakingCall = vAccess.getASuccessor() and
  innerPtrTakingCall.getASuccessor() = gcTriggerCall and
  gcTriggerCall.getASuccessor() = pointerUsageAccess and
  pointerUsageAccess.getASuccessor() = guardedPtrAccess 
  and DataFlow::localFlow(vNode, guardedPtrNode)

select v