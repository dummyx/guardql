import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph
import guard_checker

from ValueVariable v
where
  not exists(
    VariableAccess vAccess, GuardedPtr guardedPtr, PointerVariableAccess guardedPtrAccess,
    DataFlow::Node vNode, DataFlow::Node guardedPtrNode, DataFlow::Node pointerNode,
    InnerPointerTakingFunctionCallByType innerPtrTakingCall, GcTriggerCall gcTriggerCall,
    PointerVariableAccess pointerUsageAccess
  |
    vAccess = v.getAnAccess() and
    guardedPtrAccess = guardedPtr.getAnAccess() and
  
    
    vNode.asExpr() = vAccess and
    guardedPtrNode.asExpr() = guardedPtrAccess and
    pointerNode.asExpr() = pointerUsageAccess and
    DataFlow::localFlow(vNode, pointerNode) and
    
    innerPtrTakingCall = vAccess.getASuccessor*() and
    innerPtrTakingCall.getASuccessor*() = gcTriggerCall and
    gcTriggerCall.getASuccessor*() = pointerUsageAccess and
    pointerUsageAccess.getASuccessor*() = guardedPtrAccess and
    
    DataFlow::localFlow(vNode, guardedPtrNode)
  )
select v