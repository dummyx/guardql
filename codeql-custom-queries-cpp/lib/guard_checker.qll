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
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isTarget(v) and
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
  // not exists(Parameter p | v = p) and
  not v.getFile().toString().matches("%.h") and
  not v.getADeclarationEntry().isInMacroExpansion() and
  not v.getFile().toString().matches("%.inc") and
  not v.getFile().toString().matches("%.y") and
  not v.getFile().toString().matches("%.erb") and
  //ignore generated files
  not v.getFile().toString().matches("api_nodes.c")
}
