import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

from 
  ValueVariable v,
  VariableAccess vAccess,

  GuardedPtr guardedPtr,
  PointerVariableAccess guardedPtrAccess,
  DataFlow::Node vNode,
  DataFlow::Node guardedPtrNode,
  DataFlow::Node pointerNode,

  InnerPointerTakingFunctionCallByType innerPtrTakingCall,

  GcTriggerCall gcTriggerCall,
  PointerVariableAccess pointerInitAccess,
  PointerVariableAccess pointerUsageAccess,
  Assignment pointerAssignment,
  GcTriggerFunction funcInQuestion
where
  // vAccess = v.getAnAccess() and

  // scope constraint 
  funcInQuestion = vAccess.getEnclosingFunction() and
  guardedPtrAccess = funcInQuestion.getASuccessor*() and
  pointerInitAccess = funcInQuestion.getASuccessor*() and
  pointerUsageAccess = funcInQuestion.getASuccessor*() and
  pointerAssignment = funcInQuestion.getASuccessor*() and
  
  guardedPtrAccess = guardedPtr.getAnAccess() and
  vNode.asVariable() = v and
  
  guardedPtrNode.asExpr() = guardedPtrAccess and

  // inner pointer taken and assigned
  pointerInitAccess = innerPtrTakingCall.getAnArgument() or (
    pointerAssignment.getLValue() = pointerInitAccess and
    pointerAssignment.getRValue() = innerPtrTakingCall
  )  and

  pointerNode.asExpr() = pointerUsageAccess and

  DataFlow::localFlow(vNode, pointerNode) and

  // appears in right order
  // takes inner pointer -> gc trigger -> inner pointer usage -> guard
  // innerPtrTakingCall = vAccess.getASuccessor() and
  innerPtrTakingCall.getASuccessor() = gcTriggerCall and
  gcTriggerCall.getASuccessor() = pointerUsageAccess and
  pointerUsageAccess.getASuccessor() = guardedPtrAccess 
  
  // guard
  and 
  DataFlow::localFlowStep(vNode, guardedPtrNode)

select v