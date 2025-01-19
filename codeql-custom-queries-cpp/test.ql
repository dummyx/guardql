import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph
import guard_checker

from ValueVariable v
where
  exists(
    VariableAccess vAccess, PointerVariableAccess guardedPtrAccess,
    DataFlow::Node vNode, DataFlow::Node guardedPtrNode, DataFlow::Node pointerNode,
    InnerPointerTakingFunctionCallByType innerPtrTakingCall, GcTriggerCall gcTriggerCall,
    PointerVariableAccess pointerInitAccess, PointerVariableAccess pointerUsageAccess,
    Assignment pointerAssignment
  |
    vAccess = v.getAnAccess() and
    vNode.asVariable() = v and
    guardedPtrNode.asExpr() = guardedPtrAccess and
    // inner pointer taken and assigned
    pointerInitAccess = innerPtrTakingCall.getAnArgument()
    or
    (
      pointerAssignment.getLValue() = pointerInitAccess and
      pointerAssignment.getRValue() = innerPtrTakingCall
    ) and
    pointerNode.asExpr() = pointerUsageAccess and
    DataFlow::localFlow(vNode, pointerNode) and
    // appears in right order
    // takes inner pointer -> gc trigger -> inner pointer usage -> guard
    innerPtrTakingCall = vAccess.getASuccessor() and
    innerPtrTakingCall.getASuccessor() = gcTriggerCall and
    gcTriggerCall.getASuccessor() = pointerUsageAccess and
    pointerUsageAccess.getASuccessor() = guardedPtrAccess and
    // guard
    DataFlow::localFlow(vNode, guardedPtrNode)
  )
select v
