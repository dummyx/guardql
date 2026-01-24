import types
import patterns
import cpp
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
  or
  exists(MacroInvocation mi, ValueAccess va |
    mi.getMacroName() = "RB_GC_GUARD" and
    mi.getAnExpandedElement() = va and
    va.getTarget() = v
  )
  or
  exists(FunctionCall call, AddressOfExpr addr |
    call.getTarget().getName() = "rb_gc_guarded_ptr" and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().(ValueAccess).getTarget() = v
  )
  or
  exists(FunctionCall call, AddressOfExpr addr |
    call.getTarget().getName() = "rb_gc_guarded_ptr_val" and
    call.getAnArgumentSubExpr(0).getAChild*() = addr and
    addr.getAnOperand().(ValueAccess).getTarget() = v
  )
}

predicate isGcTrigger(Function function) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = function and
    (
      call.getTarget().getName() = "gc_enter" or
      isAllocOrGcCall(call) or
      isNoGvlFunction(call.getTarget())
    )
  )
}

predicate isAllocOrGcCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_get_path",
      "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_str_catf", "rb_str_cat_cstr", "rb_str_cat2", "rb_str_tmp_new",
      "rb_str_dup", "rb_str_dup_frozen", "rb_str_subseq", "rb_str_conv_enc",
      "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store",
      "rb_hash_new", "rb_hash_aset", "rb_hash_lookup2",
      "rb_obj_alloc", "rb_class_new_instance", "rb_imemo_new"
    ]
  or
  call.getTarget().getName().matches("rb_str_.*")
  or
  call.getTarget().getName().matches("rb_ary_.*")
  or
  call.getTarget().getName().matches("rb_hash_.*")
  or
  call.getTarget().getName().matches("rb_.*")
  or
  isRubyCallbackTrigger(call.getTarget())
}


class GcTriggerFunction extends Function {
  GcTriggerFunction() { isGcTrigger(this) }
}

predicate isNoGvlFunction(Function function) {
  function.getName() in ["rb_thread_call_without_gvl", "rb_thread_call_without_gvl2", "rb_nogvl"]
}

predicate isRubyCallbackTrigger(Function function) {
  function.getName() in [
      "rb_protect", "rb_rescue", "rb_rescue2", "rb_ensure", "rb_block_call", "rb_iterate",
      "rb_eval_string", "rb_eval_string_protect"
    ] or
  function.getName().matches("rb_funcall.*") or
  function.getName().matches("rb_yield.*")
}

predicate isNoreturnFunction(Function function) {
  function.getAnAttribute().hasName("noreturn")
  or
  function.getName() in [
      "rb_raise", "rb_raise_jump",
      "rb_sys_fail", "rb_sys_fail_path",
      "rb_syserr_fail", "rb_syserr_fail_path", "rb_syserr_fail_str",
      "rb_exc_raise", "rb_exc_fatal",
      "rb_fatal", "rb_bug", "rb_bug_errno",
      "rb_memerror", "rb_notimplement",
      "rb_jump_tag", "rb_throw", "rb_throw_obj"
    ]
}

predicate isNoreturnAccess(ValueAccess vAccess) {
  exists(FunctionCall fc |
    fc.getAnArgument().getAChild*() = vAccess and
    isNoreturnFunction(fc.getTarget())
  )
}

predicate exprIsOrCastsTo(Expr expr, Expr target) {
  expr = target
  or
  exists(Conversion conv |
    conv = expr and
    not conv.isImplicit() and
    exprIsOrCastsTo(conv.getExpr(), target)
  )
}

predicate isTrackedInnerPointer(InnerPointerTakingExpr innerPointerTaking) {
  innerPointerTaking.getType() instanceof PointerType
}


predicate innerPointerTakingRelatedToValue(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  (
    isTrackedInnerPointer(innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    not exists(Assignment assign | assign.getLValue() = innerPointerTaking) and
    not exists(CrementOperation crement | crement.getOperand() = innerPointerTaking)
  )
  or
  exists(PointerVariable innerPointer |
    hasTypedDataOutParamPointer(v, innerPointer, innerPointerTaking)
  )
}

predicate innerPointerBeforeGc(InnerPointerTakingExpr innerPointerTaking, GcTriggerCall gtc) {
  innerPointerTaking.getEnclosingFunction() = gtc.getEnclosingFunction() and
  (
    innerPointerTaking.getLocation().getEndLine() <= gtc.getLocation().getStartLine() or
    exists(InnerPointerTakingMacroInvocation mi |
      innerPointerTaking = mi.getExpr() and
      mi.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
    ) or
    innerPointerTaking.getEnclosingStmt() = gtc.getEnclosingStmt()
  )
}

pragma[inline]
predicate needsGuard(ValueVariable v) {
  exists(
    GcTriggerCall gtc, PointerVariable innerPointer, PointerVariableAccess pointerUsageAccess,
    InnerPointerTakingExpr innerPointerTaking |
    needsGuard(v, innerPointer, gtc, pointerUsageAccess, innerPointerTaking)
  )
  or
  exists(
    GcTriggerCall gtc, PointerVariable innerPointer, PointerVariableAccess pointerUsageAccess,
    InnerPointerTakingExpr innerPointerTaking |
    needsGuardViaPointerVarPassed(v, innerPointer, gtc, pointerUsageAccess, innerPointerTaking)
  )
  or
  exists(GcTriggerCall gtc, InnerPointerTakingExpr innerPointerTaking |
    needsGuardDirectUse(v, gtc, innerPointerTaking)
  )
  or
  exists(GcTriggerCall gtc, InnerPointerTakingExpr innerPointerTaking |
    needsGuardDirectUsePassed(v, gtc, innerPointerTaking)
  )
  or
  needsGuardArrayPtrFuncall2(v)
  or
  needsGuardViaFilePathValue(v)
}


predicate isExprCallToGcTrigger(ExprCall call) {
  exists(FunctionAccess fa |
    call.getExpr().getAChild*() = fa and
    (
      fa.getTarget() instanceof GcTriggerFunction or
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
        isAllocOrGcCall(this.(FunctionCall)) or
        this.(FunctionCall).getTarget() instanceof GcTriggerFunction or
        isNoGvlFunction(this.(FunctionCall).getTarget())
      )
    )
    or
    (
      this instanceof ExprCall and
      isExprCallToGcTrigger(this.(ExprCall))
    )
  }
}

predicate isPointerConsumingGcTriggerCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    call.getTarget().getName() in [
        "rb_str_new",
        "rb_str_new_cstr",
        "rb_str_new2",
        "rb_str_new_static",
        "rb_str_new_frozen",
        "rb_str_new_with_class",
        "rb_str_buf_new",
        "rb_str_buf_cat",
        "rb_str_cat",
        "rb_str_cat2",
        "rb_str_cat_cstr",
        "rb_str_catf",
        "rb_str_append",
        "rb_str_concat",
        "rb_str_subseq",
        "rb_str_tmp_new",
        "rb_enc_str_new",
        "rb_utf8_str_new",
        "rb_usascii_str_new",
        "rb_external_str_new",
        "rb_external_str_new_with_enc",
        "rb_external_str_new_cstr"
      ]
  )
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

predicate isScanArgsDerivedValue(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  exists(FunctionCall scanCall |
    isScanArgsOutParamWrite(scanCall, v) and
    scanCall.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    scanCall.getLocation().getEndLine() <= innerPointerTaking.getLocation().getStartLine()
  )
}

predicate valueAliasAssignedBeforeGc(ValueVariable alias, ValueVariable src, GcTriggerCall gtc) {
  exists(Assignment assign |
    assign.getLValue().getAChild*().(ValueAccess).getTarget() = alias and
    assign.getRValue().getAChild*().(ValueAccess).getTarget() = src and
    assign.getEnclosingFunction() = gtc.getEnclosingFunction() and
    assign.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
  )
  or
  exists(VariableDeclarationEntry decl |
    decl.getVariable() = alias and
    decl.getVariable().getInitializer().getExpr().getAChild*().(ValueAccess).getTarget() = src and
    decl.getVariable().getParentScope*().(Function) = gtc.getEnclosingFunction() and
    decl.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
  )
}

predicate macroArgNameEquals(InnerPointerTakingMacroInvocation mi, int idx, string name) {
  mi.getUnexpandedArgument(idx).regexpCapture(".*?([A-Za-z_][A-Za-z0-9_]*)", 1) = name
}

predicate typedDataMacroOutParamIndex(InnerPointerTakingMacroInvocation mi, int idx) {
  mi.getMacroName() = "TypedData_Make_Struct" and idx = 3
  or
  mi.getMacroName() = "TypedData_Wrap_Struct" and idx = 2
  or
  mi.getMacroName() = "Data_Make_Struct" and idx = 4
  or
  mi.getMacroName() = "Data_Wrap_Struct" and idx = 3
}

predicate hasTypedDataOutParamPointer(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(InnerPointerTakingFunctionByNameCall fc |
    fc = innerPointerTaking and
    fc.getTarget().getName() in [
        "TypedData_Make_Struct", "TypedData_Wrap_Struct",
        "Data_Make_Struct", "Data_Wrap_Struct",
        "rb_data_typed_object_make", "rb_data_typed_object_zalloc", "rb_data_typed_object_wrap",
        "rb_data_object_make", "rb_data_object_zalloc", "rb_data_object_wrap"
      ] and
    fc.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() = innerPointer and
    (
      exists(Assignment assign |
        assign.getRValue() = innerPointerTaking and
        assign.getLValue().getAChild*().(ValueAccess).getTarget() = v
      )
      or
      exists(VariableDeclarationEntry decl |
        decl.getVariable() = v and
        decl.getVariable().getInitializer().getExpr() = innerPointerTaking
      )
    )
  )
  or
  exists(InnerPointerTakingMacroInvocation mi, int idx |
    innerPointerTaking = mi.getExpr() and
    typedDataMacroOutParamIndex(mi, idx) and
    macroArgNameEquals(mi, idx, innerPointer.getName()) and
    (
      exists(Assignment assign |
        assign.getRValue() = innerPointerTaking and
        assign.getLValue().getAChild*().(ValueAccess).getTarget() = v
      )
      or
      exists(VariableDeclarationEntry decl |
        decl.getVariable() = v and
        decl.getVariable().getInitializer().getExpr() = innerPointerTaking
      )
    )
  )
}

pragma[inline]
predicate needsGuard(
  ValueVariable v, PointerVariable innerPointer, GcTriggerCall gtc,
  PointerVariableAccess pointerUsageAccess, InnerPointerTakingExpr innerPointerTaking
) {
  (
  gtc.getControlFlowScope() = v.getParentScope*().(Function) and
  gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isTarget(v) and
  innerPointer != v and
  pointerUsageAccess.getTarget() = innerPointer and
  isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc) and
  notAccessedAfterGcTrigger(v, gtc) and
  (
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
    or
    exists(ValueVariable src |
      valueAliasAssignedBeforeGc(v, src, gtc) and
      hasInnerPointerTaken(src, innerPointer, innerPointerTaking)
    )
  ) and
  not isScanArgsDerivedValue(v, innerPointerTaking)
}

pragma[inline]
predicate needsGuardDirectUse(
  ValueVariable v, GcTriggerCall gtc, InnerPointerTakingExpr innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isTarget(v) and
  innerPointerBeforeGc(innerPointerTaking, gtc) and
  isPointerUsedAfterGcTrigger(innerPointerTaking, gtc) and
  notAccessedAfterGcTrigger(v, gtc) and
  innerPointerTakingUsesValue(innerPointerTaking, v) and
  not isScanArgsDerivedValue(v, innerPointerTaking)
}

pragma[inline]
predicate needsGuardViaPointerVarPassed(
  ValueVariable v, PointerVariable innerPointer, GcTriggerCall gtc,
  PointerVariableAccess pointerUsageAccess, InnerPointerTakingExpr innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isTarget(v) and
  innerPointer != v and
  pointerUsageAccess.getTarget() = innerPointer and
  pointerVarPassedToGcTriggerCall(innerPointer, innerPointerTaking, gtc, pointerUsageAccess) and
  (
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
    or
    exists(ValueVariable src |
      valueAliasAssignedBeforeGc(v, src, gtc) and
      hasInnerPointerTaken(src, innerPointer, innerPointerTaking)
    )
  ) and
  not isScanArgsDerivedValue(v, innerPointerTaking)
}

pragma[inline]
predicate needsGuardDirectUsePassed(
  ValueVariable v, GcTriggerCall gtc, InnerPointerTakingExpr innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
  gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isTarget(v) and
  innerPointerBeforeGc(innerPointerTaking, gtc) and
  innerPointerPassedToGcTriggerCall(v, innerPointerTaking, gtc) and
  innerPointerTakingUsesValue(innerPointerTaking, v) and
  not isScanArgsDerivedValue(v, innerPointerTaking)
}

predicate needsGuardArrayPtrFuncall2(ValueVariable v) {
  exists(MacroInvocation call, InnerPointerTakingMacroInvocation mi |
    isTarget(v) and
    call.getMacroName() = "rb_funcall2" and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    mi.getMacroName() = "RARRAY_CONST_PTR" and
    mi.getExpr().getEnclosingStmt() = call.getExpr().getEnclosingStmt() and
    mi.getExpr().getAChild*().(ValueAccess).getTarget() = v and
    not isScanArgsDerivedValue(v, mi.getExpr())
  )
}

predicate needsGuardViaFilePathValue(ValueVariable v) {
  exists(InnerPointerTakingMacroInvocation mi |
    mi.getMacroName() = "FilePathValue" and
    macroInvocationUsesValue(mi, v)
  )
}


predicate innerPointerPassedToGcTriggerCall(
  ValueVariable v, InnerPointerTakingExpr innerPointerTaking, GcTriggerCall gtc
) {
  innerPointerTaking.getEnclosingFunction() = gtc.getEnclosingFunction() and
  (
    isStringInnerPointerTaking(innerPointerTaking) and
    isPointerConsumingGcTriggerCall(gtc)
    or
    isArrayInnerPointerTaking(innerPointerTaking) and
    isArrayPointerConsumingGcTriggerCall(gtc)
  ) and
  (
    innerPointerTaking.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
    or
    exists(InnerPointerTakingMacroInvocation mi |
      innerPointerTaking = mi.getExpr() and
      mi.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
    )
  ) and
  innerPointerTakingUsesValue(innerPointerTaking, v) and
  exists(Expr arg |
    gtc.getAnArgument() = arg and
    arg.getAChild*() = innerPointerTaking
  )
}

predicate pointerVarPassedToGcTriggerCall(
  PointerVariable innerPointer, InnerPointerTakingExpr innerPointerTaking,
  GcTriggerCall gtc, PointerVariableAccess pointerUsageAccess
) {
  pointerUsageAccess.getTarget() = innerPointer and
  (
    isStringInnerPointerTaking(innerPointerTaking) and
    isPointerConsumingGcTriggerCall(gtc)
    or
    isArrayInnerPointerTaking(innerPointerTaking) and
    isArrayPointerConsumingGcTriggerCall(gtc)
  ) and
  (
    innerPointerTaking.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
    or
    exists(InnerPointerTakingMacroInvocation mi |
      innerPointerTaking = mi.getExpr() and
      mi.getLocation().getEndLine() <= gtc.getLocation().getStartLine()
    )
  ) and
  exists(Expr arg |
    gtc.getAnArgument() = arg and
    arg.getAChild*() = pointerUsageAccess
  )
}

predicate isStringInnerPointerTaking(InnerPointerTakingExpr innerPointerTaking) {
  exists(InnerPointerTakingMacroInvocation mi |
    innerPointerTaking = mi.getExpr() and
    mi.getMacroName() in [
        "RSTRING_PTR", "RSTRING_END", "RSTRING_GETMEM",
        "StringValuePtr", "StringValueCStr",
        "rb_string_value_ptr", "rb_string_value_cstr"
      ]
  )
  or
  exists(InnerPointerTakingFunctionByNameCall fc |
    innerPointerTaking = fc and
    fc.getTarget().getName() in [
        "RSTRING_PTR", "RSTRING_END", "RSTRING_GETMEM",
        "StringValuePtr", "StringValueCStr",
        "rb_string_value_ptr", "rb_string_value_cstr"
      ]
  )
}

predicate isArrayPointerConsumingGcTriggerCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    call.getTarget().getName() in ["rb_funcall2"]
  )
}

predicate isArrayInnerPointerTaking(InnerPointerTakingExpr innerPointerTaking) {
  exists(InnerPointerTakingMacroInvocation mi |
    innerPointerTaking = mi.getExpr() and
    mi.getMacroName() in ["RARRAY_PTR", "RARRAY_CONST_PTR"]
  )
  or
  exists(InnerPointerTakingFunctionByNameCall fc |
    innerPointerTaking = fc and
    fc.getTarget().getName() in ["RARRAY_PTR", "RARRAY_CONST_PTR"]
  )
}


predicate isGuardAccess(ValueAccess vAccess) {
  exists(VariableDeclarationEntry declEntry, GuardedPtr guardPtr |
    declEntry.getVariable() = guardPtr and
    guardPtr.getName() = "rb_gc_guarded_ptr" and
    guardPtr.getInitializer().getExpr().getAChild*() = vAccess
  )
  or
  exists(MacroInvocation mi |
    mi.getMacroName() = "RB_GC_GUARD" and
    mi.getAnExpandedElement() = vAccess
  )
  or
  exists(FunctionCall call, AddressOfExpr addr |
    call.getTarget().getName() = "rb_gc_guarded_ptr" and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().getAChild*() = vAccess
  )
  or
  exists(FunctionCall call, AddressOfExpr addr |
    call.getTarget().getName() = "rb_gc_guarded_ptr_val" and
    call.getAnArgumentSubExpr(0).getAChild*() = addr and
    addr.getAnOperand().getAChild*() = vAccess
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

predicate isSelfParameter(ValueVariable v) {
  v instanceof Parameter and
  v.getName() = "self"
}

predicate hasInnerPointerUse(ValueVariable v) {
  exists(PointerVariable p, InnerPointerTakingExpr it, PointerVariableAccess pva, GcTriggerCall gtc |
    it.getEnclosingFunction() = v.getParentScope*().(Function) and
    hasInnerPointerTaken(v, p, it) and
    pva.getTarget() = p and
    gtc.getEnclosingFunction() = it.getEnclosingFunction() and
    it.getLocation().getEndLine() <= gtc.getLocation().getStartLine() and
    pva.getLocation().getStartLine() > gtc.getLocation().getEndLine()
  )
  or
  exists(InnerPointerTakingExpr it, GcTriggerCall gtc |
    it.getEnclosingFunction() = v.getParentScope*().(Function) and
    innerPointerTakingRelatedToValue(v, it) and
    gtc.getEnclosingFunction() = it.getEnclosingFunction() and
    gtc.getLocation().getEndLine() < it.getLocation().getStartLine()
  )
}

predicate isGuardCandidate(ValueVariable v) {
  isTarget(v) and
  not isSelfParameter(v) and
  hasInnerPointerUse(v)
}
