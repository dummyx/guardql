import types
import patterns
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph
import semmle.code.cpp.controlflow.Dominance

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

/**
 * Functions that call known allocation/GC-triggering routines (e.g., rb_str_new, rb_ary_push).
 * This widens GC trigger detection to cover common Ruby API allocators beyond gc_enter.
 */
predicate isAllocOrGcFunction(Function function) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = function and
    isAllocOrGcCall(call)
  )
}

predicate isAllocOrGcCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store",
      "rb_hash_new", "rb_hash_aset", "rb_hash_lookup2",
      "rb_obj_alloc", "rb_class_new_instance", "rb_funcall",
      "ALLOC", "ALLOC_N", "REALLOC_N"
    ]
  or
  call.getTarget() instanceof GcTriggerFunction
}

predicate isGcTrigger1(Function function) {
  exists(Expr s, Call call |
    s.getEnclosingFunction() = function and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger1(call.getTarget()))
  )
}

predicate mightCreateNewObject(Function function) {
  isNewObject(function) and
  (
    function.getType().getName().matches("%VALUE") or
    function.getAParameter().getType().getName().matches("%VALUE")
  )
}

predicate isNewObject(Function function) {
  exists(Expr s, Call call |
    s.getEnclosingFunction() = function and
    s.getAChild*() = call and
    (call.getTarget().getName() in ["malloc", "calloc"] or isNewObject(call.getTarget()))
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
  GcTriggerFunction() { isGcTrigger(this) or isAllocOrGcFunction(this) }
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

predicate needsGuard(
  ValueVariable v, PointerVariable innerPointer, GcTriggerCall gtc,
  ControlFlowNode pointerAccess, ControlFlowNode innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  // Ensure the pointer is derived before a GC trigger happens
  after(innerPointerTaking, gtc) and
  isTarget(v) and
  // residue
  // isInitialVariableAccess(v.getAnAccess(), v) and
  innerPointer != v and
  pointerAccess.(PointerVariableAccess).getTarget() = innerPointer and
  after(innerPointerTaking, pointerAccess) and
  (
    isPointerUsedAfterGcTrigger(pointerAccess, gtc)
    or
    pointerPassedToGcAlloc(gtc, pointerAccess)
    or
    exists(GcTriggerCall gtcInter |
      gtcInter.getAnArgument() = pointerAccess or gtc.getAnArgument() = innerPointerTaking
    )
  ) and
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

predicate isTarget(ValueVariable v) {
  v.getEnclosingElement() instanceof TopLevelFunction and
  // v.getIniti and
  // not exists(Parameter p | v = p) and
  not v.getFile().toString().matches("%.h") and
  not v.getADeclarationEntry().isInMacroExpansion() and
  not v.getFile().toString().matches("%.inc") and
  not v.getFile().toString().matches("%.y") and
  not v.getFile().toString().matches("%.erb") and
  //ignore generated files
  not v.getFile().toString().matches("api_nodes.c")
}
