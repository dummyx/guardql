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
        "RSTRING_PTR",
        "RSTRING_END",
        "RSTRING_GETMEM",
        "RARRAY_PTR",
        "RARRAY_CONST_PTR",
        "RARRAY_PTR_USE",
        "rb_array_const_ptr",
        "rb_ary_ptr_use_start",
        "rb_ary_ptr_use_end",
        "DATA_PTR",
        "rb_data_object_get",
        "Data_Get_Struct",
        "RTYPEDDATA_DATA",
        "RTYPEDDATA_GET_DATA",
        "TypedData_Get_Struct",
        "rb_check_typeddata",
        "RREGEXP_PTR",
        "RREGEXP_SRC_PTR",
        "RSTRUCT_PTR",
        "rb_struct_ptr",
        "ROBJECT_IVPTR",
        "RFILE",
        "RB_IO_POINTER",
        "GetOpenFile",
        "RMATCH",
        "RMATCH_EXT",
        "RMATCH_REGS",
        "StringValuePtr",
        "StringValueCStr",
        "rb_string_value_ptr",
        "rb_string_value_cstr",
        "rb_gc_guarded_ptr",
        "rb_gc_guarded_ptr_val",
        "FilePathValue",
        "rb_fd_ptr",
        "rb_memory_view_get_item_pointer",
        "rb_ractor_local_storage_ptr",
        "rb_errno_ptr",
        "rb_ruby_verbose_ptr",
        "rb_ruby_debug_ptr"
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

predicate needsGuard(
  ValueVariable v, PointerVariable innerPointer, GcTriggerCall gtc,
  PointerVariableAccess pointerUsageAccess, ControlFlowNode innerPointerTaking
) {
  (
    v.getParentScope*().(Function) = gtc.getEnclosingFunction() and
    gtc.getEnclosingFunction() = innerPointerTaking.getEnclosingElement*().(Function)
  ) and
  isTarget(v) and
  v.getAnAccess().getASuccessor*() = gtc and
  // residue
  // isInitialVariableAccess(v.getAnAccess(), v) and
  innerPointer != v and
  pointerUsageAccess.getTarget() = innerPointer and
  isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc) and
  // disable interprocedural pointer usage for now
  // and not exists(ValueAccess va | gtc.getASuccessor*() = va)
  /*
   * or
   *      passedToGcTrigger(v, initVAccess.(ValueAccess), gcTriggerCall)
   */

  notAccessedAfterGcTrigger(v, gtc) and
  hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
}

predicate isGuardAccess(ValueAccess vAccess) {
  exists(VariableDeclarationEntry declEntry, GuardedPtr guardPtr |
    declEntry.getVariable() = guardPtr and
    guardPtr.getName() = "rb_gc_guarded_ptr" and
    guardPtr.getInitializer().getExpr().getAChild*() = vAccess
  )
}

string getGuardInsertionLine(ValueVariable v) {
  result = v.getDefinitionLocation().getEndLine().toString()
}

string getGuardInsertionLineEOS(ValueVariable v) {
  if v.getParentScope() instanceof BlockStmt
  then result = v.getParentScope().(BlockStmt).getLastStmt().getLocation().getEndLine().toString()
  else
    if v.getParentScope() instanceof Function
    then
      result =
        v.getParentScope().(Function).getBlock().getLastStmt().getLocation().getEndLine().toString()
    else result = "none"
  // result = v.getDefinitionLocation().getEndLine().toString()
}

string getGuardInsertionLineBR(ValueVariable v) {
  if
    exists(ReturnStmt rstmt |
      v.getAnAccess().getASuccessor+() = rstmt and
      not exists(ReturnStmt lrstmt | lrstmt = rstmt.getASuccessor+()) and
      result = rstmt.getLocation().getEndLine().toString()
    )
  then any()
  else result = v.getParentScope().getLocation().getEndLine().toString()
}

string getGuardInsertionLineBRLA(ValueVariable v) {
  exists(ValueAccess lva |
    not exists(ValueAccess va | va = lva.getASuccessor+()) and
    result = lva.getLocation().getEndLine().toString()
  )
}

predicate isTarget(ValueVariable v) {
  v.getEnclosingElement() instanceof TopLevelFunction and
  // v.getIniti and
  not exists(Parameter p | v = p) and
  not v.getFile().toString().matches("%.h") and
  not v.getADeclarationEntry().isInMacroExpansion() and
  not v.getFile().toString().matches("%.inc") and
  not v.getFile().toString().matches("%.y") and
  not v.getFile().toString().matches("%.erb") and
  //ignore generated files
  not v.getFile().toString().matches("api_nodes.c")
}
