import types
import patterns
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

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

predicate isGcTrigger(Function function) {
  exists(Expr s, Call call |
    s = function.getAPredecessor*() and
    s instanceof FunctionCall and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger(call.getTarget()))
  )
}

predicate isGcTrigger1(Function function) {
  exists(Expr s, Call call |
    s.getEnclosingFunction() = function and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger1(call.getTarget()))
  )
}

predicate reachable(Function f, Function g) {
  f = g
  or
  exists(Function mid, FunctionCall call |
    reachable(f, mid) and
    call.getEnclosingFunction() = mid and
    call.getTarget() = g
  )
}

/**
 * 関数 f の呼び出し先（再帰的に）に foo を呼ぶ関数が含まれていれば true
 */
predicate isGcTrigger3(Function f) {
  exists(Function g |
    reachable(f, g) and
    exists(FunctionCall call |
      call.getEnclosingFunction() = g and
      call.getTarget().hasName("gc_enter")
    )
  )
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
    else none()
  }
}

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

predicate isArgumentNotSafe(GcTriggerFunction gcTriggerFunc, int i) {
  exists(GcTriggerCall innerGcTriggerCall, VariableAccess pAccess |
    gcTriggerFunc.getAPredecessor+() = innerGcTriggerCall and
    pAccess = innerGcTriggerCall.getASuccessor+() and
    gcTriggerFunc.getParameter(i).getAnAccess() = pAccess
  )
  or
  exists(GcTriggerCall recursiveGcTriggerCall, int j |
    recursiveGcTriggerCall = gcTriggerFunc.getAPredecessor+() and
    gcTriggerFunc.getParameter(i).getAnAccess() = recursiveGcTriggerCall.getAnArgumentSubExpr(j) and
    isArgumentNotSafe(recursiveGcTriggerCall.getTarget(), j)
  )
}

predicate isNeedGuard(ValueVariable v) {
  exists(ControlFlowNode initVAccess, GcTriggerCall gcTriggerCall |
    initVAccess.getASuccessor*() = gcTriggerCall and
    (
      exists(PointerVariableAccess pointerUsageAccess, PointerVariable innerPointer |
        isInitialVariableAccess(initVAccess, v) and
        pointerUsageAccess.getTarget() = innerPointer and
        hasInnerPointerTakenPattern(v, innerPointer) and
        isPointerUsedAfterGcTrigger(pointerUsageAccess, gcTriggerCall)
      )
      or
      passedToGcTrigger(v, initVAccess.(ValueAccess), gcTriggerCall)
    ) and
    accessedAfterGcTrigger(v, gcTriggerCall)
  )
}

predicate isGuardAccess(ValueAccess vAccess) {
  exists(VariableDeclarationEntry declEntry, GuardedPtr guardPtr |
    declEntry.getVariable() = guardPtr and
    guardPtr.getName() = "rb_gc_guarded_ptr" and
    guardPtr.getInitializer().getExpr().getAChild*() = vAccess
  )
}


/**
 * Broader pattern detection for variables that might need guards
 */
predicate mightNeedGuard(ValueVariable v) {
  exists(FunctionCall innerPtrCall |
    // Inner pointer extraction from the variable
    innerPtrCall.getTarget().getName() in [
        "RSTRING_PTR", "RARRAY_PTR", "RARRAY_CONST_PTR", "RHASH_TBL", "RSTRUCT_PTR", "DATA_PTR",
        "RREGEXP_PTR", "RFILE_PTR", "rb_string_value_ptr", "rb_string_value_cstr", "StringValueCStr"
      ] and
    innerPtrCall.getAnArgument().(VariableAccess).getTarget() = v
  )
  or
  exists(FunctionCall allocCall |
    // Variable used around allocation calls
    allocCall.getTarget().getName().matches("rb_%") and
    (
      allocCall.getTarget().getName().matches("%new%") or
      allocCall.getTarget().getName().matches("%alloc%") or
      allocCall.getTarget().getName().matches("%resize%")
    ) and
    exists(VariableAccess vAccess |
      vAccess.getTarget() = v and
      (
        vAccess = allocCall.getASuccessor+() or
        allocCall = vAccess.getASuccessor+()
      )
    )
  )
  or
  // Variable passed to functions that might store references
  exists(FunctionCall call, VariableAccess vAccess |
    vAccess.getTarget() = v and
    call.getAnArgument() = vAccess and
    call.getTarget().getName().matches("rb_%")
  )
}

/**
 * String-specific guard detection
 */
predicate stringNeedsGuard(ValueVariable v) {
  exists(FunctionCall rStringPtr, FunctionCall potentialGc |
    // RSTRING_PTR called on variable
    rStringPtr.getTarget().hasName("RSTRING_PTR") and
    rStringPtr.getAnArgument().(VariableAccess).getTarget() = v and
    // Followed by potential GC trigger
    rStringPtr.getASuccessor+() = potentialGc and
    (
      potentialGc.getTarget().getName().matches("rb_str_%") or
      potentialGc.getTarget().getName().matches("rb_ary_%") or
      potentialGc.getTarget().getName().matches("rb_hash_%") or
      potentialGc.getTarget().getName() in ["ALLOC", "ALLOC_N", "rb_funcall"]
    )
  )
}

/**
 * Parameter-based guard detection
 */
predicate parameterNeedsGuard(ValueVariable v) {
  exists(Parameter param, Function f, FunctionCall allocCall |
    v = param and
    param.getFunction() = f and
    allocCall.getEnclosingFunction() = f and
    allocCall.getTarget().getName().matches("rb_%") and
    exists(VariableAccess laterUse |
      laterUse.getTarget() = v and
      allocCall.getASuccessor+() = laterUse
    )
  )
}

/**
 * Comprehensive guard need detection
 */
predicate comprehensiveNeedsGuard(ValueVariable v) {
  mightNeedGuard(v) or stringNeedsGuard(v) or parameterNeedsGuard(v)
}

/**
 * Check if variable is in an extension (ext/) - these often have more guards
 */
predicate isInExtension(ValueVariable v) { v.getFile().getAbsolutePath().matches("%/ext/%") }

/**
 * Check if variable name suggests it holds string data
 */
predicate isStringVariable(ValueVariable v) {
  v.getName().matches("%str%") or
  v.getName().matches("%string%") or
  v.getName().matches("%data%") or
  v.getName().matches("%buf%") or
  v.getName().matches("%msg%") or
  v.getName().matches("%text%")
}
