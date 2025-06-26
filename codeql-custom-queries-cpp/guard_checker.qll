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
  PointerVariable() { this.getType() instanceof PointerType }
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

// Configuration for tracking inner pointer usage
module InnerPointerConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(ValueVariable v | v.getAnAccess() = source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(PointerVariable valuePtr | sink.asExpr() = valuePtr.getAnAccess())
  }
}

module InnerPointerFlow = DataFlow::Global<InnerPointerConfiguration>;

predicate hasGuardByFlow(ValueVariable v) {
  exists(DataFlow::Node sink, DataFlow::Node source, GuardedPtr guardedPtr |
    sink.asExpr() = guardedPtr.getAnAccess() and
    source.asExpr() = v.getAnAccess() and
    DataFlow::localFlow(source, sink)
  )
}

predicate hasGuard(ValueVariable v) {
  exists(VariableDeclarationEntry decl |
    decl.getVariable()
        .getInitializer()
        .getExpr()
        .(AddressOfExpr)
        .getAnOperand()
        .(VariableAccess)
        .getTarget() = v and
    decl.getVariable().getName() = "rb_gc_guarded_ptr"
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
  /*
   * or
   *  exists(Variable v |
   *    v = function.getAParameter() and
   *    v.getType() instanceof FunctionPointerIshType
   *  )
   */

  }

predicate isGcTriggerWithFunctionPointer(Function function) {
  exists(Expr s, Call call |
    s = function.getAPredecessor*() and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger(call.getTarget()))
  )
  or
  exists(Variable v |
    v = function.getAParameter() and
    v.getType() instanceof FunctionPointerIshType
  )
}

class GcTriggerFunction extends Function {
  GcTriggerFunction() { isGcTrigger(this) }
}

class GcTriggerFunctionWithFunctionPointer extends Function {
  GcTriggerFunctionWithFunctionPointer() { isGcTriggerWithFunctionPointer(this) }
}

class GcTriggerCall extends FunctionCall {
  GcTriggerCall() {
    if this instanceof FunctionCall
    then this.(FunctionCall).getTarget() instanceof GcTriggerFunction
    else 1 = 0
    /*
     * else (
     *      if this instanceof VariableAccess
     *      then this.(VariableAccess).getTarget().getType() instanceof FunctionPointerType
     *      else none()
     *    )
     */

    }
}

//
class GcTriggerCallWithFunctionPointer extends Expr {
  GcTriggerCallWithFunctionPointer() {
    if this instanceof FunctionCall
    then this.(FunctionCall).getTarget() instanceof GcTriggerFunctionWithFunctionPointer
    else (
      if this instanceof VariableAccess
      then this.(VariableAccess).getTarget().getType() instanceof FunctionPointerType
      else none()
    )
  }
}

class InnerPointerTakingFunctionByNameCall extends FunctionCall {
  InnerPointerTakingFunctionByNameCall() {
    this.getTarget() instanceof InnerPointerTakingFunctionByName
  }
}

class InnerPointerTakingFunctionByName extends Function {
  InnerPointerTakingFunctionByName() {
    this.getName() in [
        "RSTRING_PTR", "RARRAY_PTR", "RHASH_TBL", "RSTRUCT_PTR", "DATA_PTR", "RREGEXP_PTR",
        "RVECTOR_PTR", "RFILE_PTR", "RBASIC", "Data_Get_Struct", "TypedData_Get_Struct",
        "rb_struct_ptr", "rb_ary_ptr", "rb_string_value_ptr", "rb_ary_const_ptr",
        "rb_array_const_ptr", "RARRAY_CONST_PTR", "RSTRING_END", "rb_reg_nth_match",
        "RTYPEDDATA_GET_DATA", "rb_string_value_cstr", "StringValueCStr", "rb_str_ptr_readonly",
        "rb_match_ptr", "rb_io_stdio_file", "RBIGNUM_DIGITS",
      ]
  }
}

//write a predicate that checks if the value of an argument of a function is used after a gc trigger call
predicate isArgumentNotSave(GcTriggerFunction gcf, int i) {
  exists(GcTriggerCall innerGcTriggerCall, PointerVariableAccess pAccess, Function f |
    gcf.getAPredecessor+() = innerGcTriggerCall and
    pAccess = innerGcTriggerCall.getASuccessor+() and
    f.getParameter(i).getAnAccess() = pAccess
  )
}

predicate isNeedGuard(ValueVariable v) {
  exists(ControlFlowNode initVAccess, GcTriggerCall gcTriggerCall |
    // PointerVariableAccess pointerUsageAccess, Expr pointerTaking, PointerVariable innerPointer
    exists(PointerVariableAccess pointerUsageAccess, PointerVariable innerPointer |
      (
        initVAccess.(ValueAccess).getTarget() = v or
        initVAccess.(Declaration).getADeclarationEntry().(VariableDeclarationEntry).getVariable() =
          v
      ) and
      pointerUsageAccess.getTarget() = innerPointer and
      gcTriggerCall = initVAccess.getASuccessor*() and
      (
        pointerUsageAccess = gcTriggerCall.getASuccessor*() or
        pointerUsageAccess = gcTriggerCall.getEnclosingBlock().getASuccessor*()
      ) and
      (
        exists(
          Assignment assignment // Case 1: Assignment where innerPointer gets a value from v
        |
          // pointerTaking = assignment and
          assignment.getLValue().getAChild*().(VariableAccess).getTarget() = innerPointer and
          assignment.getRValue().getAChild*() instanceof InnerPointerTakingFunctionByNameCall and
          assignment
              .getRValue()
              .getAChild*()
              .(InnerPointerTakingFunctionByNameCall)
              .getAnArgument()
              .(ValueAccess)
              .getTarget() = v
        )
        or
        exists(
          Declaration decl, VariableDeclarationEntry declEntry,
          InnerPointerTakingFunctionByNameCall pointerTakingCall
        |
          // pointerTakingCall = pointerTaking and
          decl.getADeclarationEntry() = declEntry and // Case 2: Declaration where innerPointer gets a value from v
          declEntry.getVariable() = innerPointer and
          innerPointer.getInitializer().getExpr() = pointerTakingCall and
          pointerTakingCall.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
        )
        or
        exists(
          InnerPointerTakingFunctionByNameCall pointerTakingCall // Case 2: Direct call (not assignment)
        |
          // pointerTaking = pointerTakingCall and
          (
            pointerTakingCall.getAnArgument().getAChild*().(ValueAccess).getTarget() = v or
            pointerTakingCall.getAnArgument().getAChild*().(FieldAccess).getQualifier() =
              v.getAnAccess()
          ) and
          pointerTakingCall.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() =
            innerPointer
        )
        /*or
        exists(int i |
          i < count(gcTriggerCall.getAnArgument()) and
          innerPointer.getAnAccess() = gcTriggerCall.getArgument(i) and
          isArgumentNotSave(gcTriggerCall.getTarget(), i)
        )*/
      )
    ) and
    not exists(VariableAccess va |
      va.getTarget() = v and va = gcTriggerCall.getASuccessor*() and not isGuardAccess(va)
    )
  )
  or
  exists(int i, GcTriggerCall gcTriggerCall |
    i < count(gcTriggerCall.getAnArgument()) and
    gcTriggerCall.getArgument(i).getAChild*() = v.getAnAccess() and
    isArgumentNotSave(gcTriggerCall.getTarget(), i) and
    gcTriggerCall.getArgument(i) != v.getAnAccess() and
    not exists(VariableAccess va |
      va.getTarget() = v and va = gcTriggerCall.getASuccessor*() and not isGuardAccess(va)
    )
  )
}

class PointerExpr extends Expr {
  PointerExpr() { this.getType() instanceof PointerType }
}

predicate isGuardAccess(ValueAccess vAccess) {
  exists(VariableDeclarationEntry declEntry, GuardedPtr gPtr |
    declEntry.getVariable() = gPtr and
    gPtr.getName() = "rb_gc_guarded_ptr" and
    gPtr.getInitializer().getExpr().getAChild*() = vAccess
  )
}
