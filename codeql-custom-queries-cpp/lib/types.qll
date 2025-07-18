import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

class ValueVariable extends Variable {
  ValueVariable() { this.getType().getName() = "VALUE" }
}

class ValueVariableMatch extends Variable {
  ValueVariableMatch() { this.getType().getName().matches("%VALUE%") }
}

class ValueAccess extends VariableAccess {
  ValueAccess() { this.getTarget() instanceof ValueVariable }
}

class PointerVariable extends Variable {
  PointerVariable() {
    this.getType() instanceof PointerType or
    this.getType().getName().matches("%VALUE%")
  }
}

class FunctionPointerAccess extends VariableAccess {
  FunctionPointerAccess() { this.getTarget().getType() instanceof FunctionPointerType }
}

class PointerVariableAccess extends VariableAccess {
  PointerVariableAccess() { this.getTarget() instanceof PointerVariable }
}

class InnerPointerTakingFunctionByType extends Function {
  InnerPointerTakingFunctionByType() {
    this.getAParameter().getType().getName() = "VALUE" and
    (
      this.getType() instanceof PointerType or
      this.getAParameter().getType() instanceof PointerType
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
