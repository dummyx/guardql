import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access


class ValueVariable extends Variable {
  ValueVariable() {
    this.getType().getName() = "VALUE"
  }
}

class InnerPointerTakingFunction extends Function {
  InnerPointerTakingFunction() {
    this.getType().getName() = "VALUE"
  }
}

class GuardFunction extends Function {
  GuardFunction() {
    this.getName() = "RB_GC_GUARD"
  }
}

predicate isObjectCreationCall(FunctionCall fc) {
  fc.getTarget().getName().matches("rb_%_new%")
}


predicate hasRBGCGUARD(ValueVariable v) {
  v.isAffectedByMacro()
}

predicate isProperlyGuarded(ControlFlowNode a, ControlFlowNode b, ControlFlowNode c) {
  successors_extended(a, b) and successors_extended(b, c) 
}

predicate isProperlyGuarded_Two(ControlFlowNode a, ControlFlowNode b) {
  b = a.getASuccessor*() 
}

from 
  ControlFlowNode cfn1, ControlFlowNode cfn2, ControlFlowNode cfn3
where
    isProperlyGuarded_Two(cfn1, cfn2)
select cfn1, cfn2, "Variable '" + "' assigned a new object may be garbage collected without RB_GC_GUARD."

