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

predicate isGcTrigger(Function function) {
  exists(Expr s, Call call |
    s = function.getAPredecessor*() and
    s instanceof FunctionCall and
    s.getAChild*() = call and
    (call.getTarget().getName() = "gc_enter" or isGcTrigger(call.getTarget()))
  )
}

predicate isAllocOrGcCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store", "rb_hash_new", "rb_hash_aset",
      "rb_hash_lookup2", "rb_obj_alloc", "rb_class_new_instance", "rb_funcall", "ALLOC", "ALLOC_N",
      "REALLOC_N"
    ]
  or
  call.getTarget() instanceof GcTriggerFunction
  or
  call.getTarget() instanceof ObjectGeneratingFunction
}

predicate isMemoryAllocCall(Call call) {
  call.getTarget().getName() in [
      "malloc", "calloc", "realloc", "reallocarray",
      "xmalloc", "xcalloc", "xrealloc", "xmalloc2", "xrealloc2",
      "ruby_xmalloc", "ruby_xcalloc", "ruby_xrealloc", "ruby_xmalloc2", "ruby_xrealloc2",
      "rb_xmalloc", "rb_xcalloc", "rb_xrealloc", "rb_xmalloc_mul_add", "rb_xmalloc_mul_add_mul",
      "ALLOC", "ALLOC_N", "REALLOC_N", "ZALLOC", "ALLOCV", "ALLOCV_N"
    ]
}

predicate isObjectGeneratingFunction(Function function) {
  function.getType().getName().matches("%VALUE%") and
  exists(Call call |
    call.getEnclosingFunction() = function and
    (isMemoryAllocCall(call) or isObjectGeneratingFunction(call.getTarget()))
  )
}

class ObjectGeneratingFunction extends Function {
  ObjectGeneratingFunction() { isObjectGeneratingFunction(this) }
}

class GcTriggerFunction extends Function {
  GcTriggerFunction() { isGcTrigger(this) }
}

predicate isNoGvlFunction(Function function) {
  function.getName() in ["rb_thread_call_without_gvl", "rb_thread_call_without_gvl2", "rb_nogvl"]
  or
  exists(Call call |
    call.getEnclosingFunction() = function and
    isNoGvlFunction(call.getTarget())
  )
}

predicate isRubyCallbackTrigger(Function function) {
  function.getName() in [
      "rb_protect", "rb_rescue", "rb_rescue2", "rb_ensure", "rb_yield",
      "rb_block_call", "rb_iterate", "rb_eval_string", "rb_eval_string_protect"
    ]
}

predicate isExprCallToGcTrigger(ExprCall call) {
  exists(FunctionAccess fa |
    call.getExpr().getAChild*() = fa and
    (
      fa.getTarget() instanceof GcTriggerFunction or
      fa.getTarget() instanceof ObjectGeneratingFunction or
      isNoGvlFunction(fa.getTarget()) or
      isRubyCallbackTrigger(fa.getTarget())
    )
  )
}

class GcTriggerCall extends Call {
  GcTriggerCall() {
    (
      this instanceof FunctionCall and
      (
        this.(FunctionCall).getTarget() instanceof GcTriggerFunction or
        this.(FunctionCall).getTarget() instanceof ObjectGeneratingFunction or
        isNoGvlFunction(this.(FunctionCall).getTarget()) or
        isRubyCallbackTrigger(this.(FunctionCall).getTarget())
      )
    )
    or
    (
      this instanceof ExprCall and
      isExprCallToGcTrigger(this.(ExprCall))
    )
  }
}

predicate isScanArgsCall(FunctionCall call) {
  call.getTarget().getName() in ["rb_scan_args", "rb_scan_args_kw"]
}

predicate isScanArgsOutParamWrite(FunctionCall call, ValueVariable v) {
  isScanArgsCall(call) and
  exists(AddressOfExpr addr |
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().(ValueAccess).getTarget() = v
  )
}

predicate valueOverwrittenByObjectGeneratingCall(ValueVariable v, ControlFlowNode changeNode) {
  exists(Assignment assign, FunctionCall call |
    changeNode = assign and
    assign.getLValue().getAChild*().(ValueAccess).getTarget() = v and
    assign.getRValue().getAChild*() = call and
    call.getTarget() instanceof ObjectGeneratingFunction
  )
  or
  exists(FunctionCall call, AddressOfExpr addr |
    changeNode = call and
    call.getTarget() instanceof ObjectGeneratingFunction and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().(ValueAccess).getTarget() = v
  )
}

predicate isScanArgsDerivedValue(ValueAccess va) {
  exists(FunctionCall scanCall |
    isScanArgsOutParamWrite(scanCall, va.getTarget()) and
    scanCall.getEnclosingFunction() = va.getEnclosingFunction() and
    scanCall.getASuccessor*() = va and
    not exists(ControlFlowNode change |
      valueOverwrittenByObjectGeneratingCall(va.getTarget(), change) and
      scanCall.getASuccessor*() = change and
      change.getASuccessor*() = va
    )
  )
}

predicate scanArgsSafeAt(ValueVariable v, InnerPointerTakingFunctionByNameCall innerPointerTaking) {
  exists(ValueAccess baseAccess |
    baseAccess.getTarget() = v and
    innerPointerTaking.getAnArgument().getAChild*() = baseAccess and
    isScanArgsDerivedValue(baseAccess)
  )
}

predicate notAccessedAfterCall(ValueVariable v, Call call) {
  not exists(VariableAccess va |
    va.getTarget() = v and va = call.getASuccessor+() and not isGuardAccess(va)
  )
}

predicate notAccessedAfterCallLocation(ValueVariable v, Call call) {
  not exists(VariableAccess va |
    va.getTarget() = v and
    va.getLocation().getStartLine() > call.getLocation().getEndLine() and
    not isGuardAccess(va)
  )
}

predicate calleeParamUsedAfterGcTrigger(
  Function callee, int idx, GcTriggerCall gtc, PointerVariableAccess paramUse
) {
  gtc.getEnclosingFunction() = callee and
  paramUse.getTarget() = callee.getParameter(idx) and
  gtc.getASuccessor+() = paramUse
}

predicate hasTypedDataOutParamPointer(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  innerPointerTaking.getTarget().getName() in [
      "TypedData_Make_Struct", "TypedData_Wrap_Struct",
      "Data_Make_Struct", "Data_Wrap_Struct"
    ] and
  innerPointerTaking.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() = innerPointer and
  (
    exists(Assignment assign |
      assign.getRValue().getAChild*() = innerPointerTaking and
      assign.getLValue().getAChild*().(ValueAccess).getTarget() = v
    )
    or
    exists(VariableDeclarationEntry decl |
      decl.getVariable() = v and
      decl.getVariable().getInitializer().getExpr() = innerPointerTaking
    )
  )
}

predicate hasDerivedPointer(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
  or
  hasTypedDataOutParamPointer(v, innerPointer, innerPointerTaking)
}

predicate interproceduralPointerUseAfterGc(
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  exists(FunctionCall call, Function callee, int idx, PointerVariableAccess paramUse |
    call.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    callee = call.getTarget() and
    (
      // Directly pass the inner-pointer expression as an argument.
      (
        call.getAnArgumentSubExpr(idx).getAChild*() = innerPointerTaking and
        innerPointerTaking.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
      )
      or
      // Pass a derived pointer variable as an argument.
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        innerPointerTaking.getASuccessor*() = call and
        call.getAnArgumentSubExpr(idx).getAChild*().(PointerVariableAccess).getTarget() = innerPointer
      )
    ) and
    calleeParamUsedAfterGcTrigger(callee, idx, gtc, paramUse) and
    pointerUsageAccess = paramUse and
    notAccessedAfterCall(v, call)
  )
}

predicate intraProceduralPointerUseAfterGc(
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  exists(PointerVariable innerPointer |
    innerPointer != v and
    pointerUsageAccess.(PointerVariableAccess).getTarget() = innerPointer and
    hasDerivedPointer(v, innerPointer, innerPointerTaking) and
    isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc)
  ) and
  notAccessedAfterGcTrigger(v, gtc)
}

predicate pointerStoredInStructPassedToCall(PointerVariable innerPointer, Call call) {
  exists(Variable structVar, FieldAccess fa, Assignment assign, AddressOfExpr addr |
    assign.getRValue().getAChild*().(PointerVariableAccess).getTarget() = innerPointer and
    assign.getLValue().getAChild*() = fa and
    fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().getAChild*().(VariableAccess).getTarget() = structVar and
    assign.getASuccessor*() = call
  )
}

predicate inlinePointerStoredInStructPassedToCall(
  ValueVariable v, InnerPointerTakingFunctionByNameCall innerPointerTaking, Call call
) {
  exists(Variable structVar, FieldAccess fa, Assignment assign, AddressOfExpr addr |
    assign.getRValue().getAChild*() = innerPointerTaking and
    innerPointerTaking.getAnArgument().getAChild*().(ValueAccess).getTarget() = v and
    assign.getLValue().getAChild*() = fa and
    fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().getAChild*().(VariableAccess).getTarget() = structVar and
    assign.getASuccessor*() = call
  )
}

predicate pointerPassedToGcTriggerCall(
  ValueVariable v, GcTriggerCall gtc,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  innerPointerTaking.getASuccessor*() = gtc and
  (
    gtc.getAnArgument().getAChild*() = innerPointerTaking and
    innerPointerTaking.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
    or
    inlinePointerStoredInStructPassedToCall(v, innerPointerTaking, gtc)
    or
    exists(PointerVariable innerPointer |
      hasDerivedPointer(v, innerPointer, innerPointerTaking) and
      (
        gtc.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() = innerPointer
        or
        pointerStoredInStructPassedToCall(innerPointer, gtc)
      )
    )
  )
}

predicate needsGuard(
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  innerPointerTaking.getEnclosingFunction() = v.getParentScope*().(Function) and
  isTarget(v) and
  not scanArgsSafeAt(v, innerPointerTaking) and
  (
    intraProceduralPointerUseAfterGc(v, gtc, pointerUsageAccess, innerPointerTaking)
    or
    interproceduralPointerUseAfterGc(v, gtc, pointerUsageAccess, innerPointerTaking)
    or
    (
      pointerPassedToGcTriggerCall(v, gtc, innerPointerTaking) and
      notAccessedAfterCallLocation(v, gtc) and
      pointerUsageAccess = innerPointerTaking
    )
  )
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
