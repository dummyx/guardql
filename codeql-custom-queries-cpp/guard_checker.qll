import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

class ValueVariable extends Variable {
  ValueVariable() { this.getType().getName() = "VALUE" }
}

class PointerVariable extends Variable {
  PointerVariable() { this.getType() instanceof PointerType }
}

class PointerVariableAccess extends VariableAccess {
  PointerVariableAccess() { this.getTarget() instanceof PointerVariable }
}

class InnerPointerTakingFunctionByType extends Function {
  InnerPointerTakingFunctionByType() {
    this.getAParameter().getType().getName() = "VALUE" and
    (
      this.getType() instanceof PointerType or
      this.getAParameter().getType()  instanceof PointerType
          )
  }
}

class InnerPointerTakingFunctionCallByType extends FunctionCall {
  InnerPointerTakingFunctionCallByType() {
    this.getTarget() instanceof InnerPointerTakingFunctionByType
  }
}

class GuardMacroInvocation extends MacroInvocation {
  GuardMacroInvocation() { this.getMacroName() = "RB_GC_GUARD" }
}

class InnerPointerTakingFunctionCall extends FunctionCall {
  InnerPointerTakingFunctionCall() {
    this.getAnArgument().getType().getName().matches("%VALUE %_") or
    this.getTarget().getType().getName().matches("%VALUE %")
  }
}

class GuardedPtr extends Variable {
  GuardedPtr() {
    this.getType().getName() = "volatile VALUE *" and
    this.getName() = "rb_gc_guarded_ptr"
  }
}

class ValuePtrVariable extends Variable {
  ValuePtrVariable() { this.getType().getName() = "VALUE *" }
}

class InnerPointerTakingFunction extends Function {
  InnerPointerTakingFunction() { this.getName() in ["rb_array_const_ptr",] }
}

// Configuration for tracking inner pointer usage
module InnerPointerConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ValueVariable v | v.getAnAccess() = source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ValuePtrVariable valuePtr | sink.asExpr() = valuePtr.getAnAccess())
  }
}

module InnerPointerFlow = DataFlow::Global<InnerPointerConfiguration>;

predicate hasGuard(ValueVariable v) {
  exists(DataFlow::Node sink, DataFlow::Node source, GuardedPtr guardedPtr |
    sink.asExpr() = guardedPtr.getAnAccess() and
    source.asExpr() = v.getAnAccess() and
    DataFlow::localFlow(source, sink)
  )
}

predicate tripleTransition(ControlFlowNode a, ControlFlowNode b, ControlFlowNode c) {
  a.getASuccessor*() = b and b.getASuccessor*() = c
}

/*
 * predicate isDirectGcTrigger(Function function) {
 *  s = function.getAPredecessor*()
 *  and s.getAChild*() = call and call.getTarget().getName() = "gc_enter"
 * }
 */

predicate isGcTrigger(Function function) {
  exists(Expr s, Call call |
    s = function.getAPredecessor*() and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger(call.getTarget()))
  )
}

class GcTriggerFunction extends Function {
  GcTriggerFunction() { isGcTrigger(this) }
}

class GcTriggerCall extends FunctionCall {
  GcTriggerCall() { this.getTarget() instanceof GcTriggerFunction }
}

predicate isInnerPointerTaken(ValueVariable v, VariableAccess pointerAccess) {
  exists(DataFlow::Node sink, DataFlow::Node source |
    sink.asExpr() = pointerAccess and
    source.asExpr() = v.getAnAccess() and
    InnerPointerFlow::flow(sink, source)
  )
}

predicate funcHasGuard(Function function) {
  exists(VariableAccess v, Expr expr |
    expr = function.getAPredecessor*() and
    v = expr.getAChild*() and
    v.getTarget().getName() = "rb_gc_guarded_ptr"
  )
}

predicate isNeedGuard(ValueVariable v) {
  exists(
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
    innerPtrTakingCall.getASuccessor*() = gcTriggerCall
  )
}



predicate isProperlyGuarded(ValueVariable v) {
  exists(
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
}