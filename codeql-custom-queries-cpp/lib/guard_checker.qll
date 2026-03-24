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

predicate isDirectGcTrigger(Function function) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = function and
    (
      call.getTarget().getName() = "gc_enter" or
      isAllocOrGcCall(call) or
      isNoGvlFunction(call.getTarget())
    )
  )
}

predicate isAllocLikeCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_get_path",
      "rb_str_new", "rb_str_new2", "rb_str_new_cstr", "rb_str_new_static", "rb_str_new_frozen",
      "rb_str_buf_new", "rb_str_buf_new2", "rb_str_buf_new_cstr",
      "rb_str_buf_cat", "rb_str_buf_cat2", "rb_str_buf_append",
      "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_str_cat", "rb_str_catf", "rb_str_cat_cstr", "rb_str_cat2",
      "rb_str_tmp_new", "rb_str_dup", "rb_str_dup_frozen", "rb_str_subseq", "rb_str_conv_enc",
      "rb_ary_new", "rb_ary_new_capa", "rb_ary_new_from_values", "rb_ary_new_from_args",
      "rb_ary_new3", "rb_ary_new4", "rb_ary_tmp_new", "rb_ary_resize",
      "rb_ary_push", "rb_ary_concat", "rb_ary_store",
      "rb_hash_new", "rb_hash_new_with_size", "rb_hash_aset", "rb_hash_lookup2", "rb_hash_dup",
      "rb_obj_alloc", "rb_class_new_instance", "rb_proc_call_with_block", "rb_imemo_new",
      "rb_enc_warn",
      "str_enc_new",
      "pm_options_filepath_set",
      "io_buffer_copy_from",
      "rb_iseq_new_with_opt",
      "bignew",
      "bignew_1",
      "rb_syserr_new",
      "rb_enc_str_buf_cat",
      "rb_filesystem_str_new_cstr",
      "rb_ary_splice",
      "ruby_brace_expand",
      "ossl_asn1_decode0",
      "gzfile_write",
      "gzfile_read_more",
      "zstream_append_input",
      // Oniguruma regex compilation allocates via `xmalloc` and can trigger GC.
      "onig_new",
      "onig_new_without_alloc",
      "rb_exec_fail",
      "make_regexp",
      "yyerror0",
      "parser_yyerror0"
    ]
}

predicate isAllocOrGcCall(FunctionCall call) {
  isAllocLikeCall(call)
  or
  isRubyCallbackTrigger(call.getTarget())
}

predicate isGcTrigger(Function function) {
  isDirectGcTrigger(function)
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
    needsGuardDirectUsePassed(v, gtc, innerPointerTaking)
  )
  or
  needsGuardViaWrappedPointer(v)
  or
  needsGuardViaStructField(v)
  or
  needsGuardArrayPtrFuncall2(v)
  or
  needsGuardViaFilePathValue(v)
  or
  needsGuardAcrossExplicitAllocator(v)
  or
  needsGuardViaKnownAllocatingCallee(v)
  or
  needsGuardKnownRequiredGuardSites(v)
  or
  needsGuardViaOneStepInterprocPointerUse(v)
}

/**
 * One-step interprocedural check:
 * - caller derives an inner pointer from `v` and passes it to `callee`
 * - callee triggers GC and then uses that pointer parameter afterwards
 * - caller does not keep `v` alive after the call
 */
cached predicate calleeUsesPointerParamAfterGc(Function callee, PointerVariable paramPtr) {
  paramPtr instanceof Parameter and
  paramPtr.getParentScope() = callee and
  exists(GcTriggerCall gtc, PointerVariableAccess use |
    gtc.getEnclosingFunction() = callee and
    use.getTarget() = paramPtr and
    gtc.getLocation().getEndLine() < use.getLocation().getStartLine() and
    not exists(Assignment assign |
      assign.getEnclosingFunction() = callee and
      assign.getLValue().getAChild*().(VariableAccess).getTarget() = paramPtr and
      assign.getLocation().getStartLine() > gtc.getLocation().getEndLine() and
      assign.getLocation().getEndLine() < use.getLocation().getStartLine()
    )
  )
}

pragma[inline]
predicate needsGuardViaOneStepInterprocPointerUse(ValueVariable v) {
  // Direct inner-pointer-taking expression passed as a callee argument.
  exists(GcTriggerCall gtc, FunctionCall call, Function callee, int i,
    PointerVariable paramPtr, InnerPointerTakingExpr innerPointerTaking
  |
    call = gtc and
    isTarget(v) and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    callee = call.getTarget() and
    i >= 0 and i < callee.getNumberOfParameters() and
    paramPtr = callee.getParameter(i) and
    paramPtr.getType() instanceof PointerType and
    exprIsOrCastsTo(call.getAnArgumentSubExpr(i), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking)) and
    calleeUsesPointerParamAfterGc(callee, paramPtr) and
    notAccessedAfterGcTrigger(v, gtc)
  )
  or
  // Pointer variable derived from `v` passed as a callee argument.
  exists(GcTriggerCall gtc, FunctionCall call, Function callee, int i,
    PointerVariable paramPtr, PointerVariable innerPointer, PointerVariableAccess argPva,
    InnerPointerTakingExpr innerPointerTaking
  |
    call = gtc and
    isTarget(v) and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    callee = call.getTarget() and
    i >= 0 and i < callee.getNumberOfParameters() and
    paramPtr = callee.getParameter(i) and
    paramPtr.getType() instanceof PointerType and
    call.getAnArgumentSubExpr(i).getAChild*() = argPva and
    argPva.getTarget() = innerPointer and
    // Ensure the pointer passed is derived from `v` before the call.
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking) and
    innerPointerTaking.getEnclosingFunction() = call.getEnclosingFunction() and
    innerPointerTaking.getLocation().getEndLine() <= call.getLocation().getStartLine() and
    (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking)) and
    calleeUsesPointerParamAfterGc(callee, paramPtr) and
    notAccessedAfterGcTrigger(v, gtc)
  )
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
    (
      call.getTarget() instanceof GcTriggerFunction
      or
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
          "rb_external_str_new_cstr",
          "rb_filesystem_str_new_cstr",
          "rb_enc_str_buf_cat",
          "rb_enc_warn",
          "rb_reg_preprocess",
          "rb_reg_expr_str",
          // Oniguruma regex compilation allocates via `xmalloc` and can trigger GC.
          "onig_new",
          "onig_new_without_alloc",
          "make_regexp",
          "yyerror0",
          "pm_options_filepath_set",
          "io_buffer_copy_from",
          "rb_syserr_new",
          "ruby_brace_expand",
          "ossl_asn1_decode0",
          "rb_exec_fail",
          "gzfile_write",
          "parser_yyerror0"
        ]
    )
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

predicate isScanArgsSafeToIgnore(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  isScanArgsDerivedValue(v, innerPointerTaking) and
  not (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking))
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

predicate wrapStructDataArgIndex(FunctionCall call, int idx) {
  call.getTarget().getName() = "TypedData_Wrap_Struct" and idx = 2
  or
  call.getTarget().getName() = "Data_Wrap_Struct" and idx = 3
  or
  call.getTarget().getName() = "rb_data_typed_object_wrap" and idx = 1
  or
  call.getTarget().getName() = "rb_data_object_wrap" and idx = 1
}

predicate wrapStructCallAssignsValue(ValueVariable v, FunctionCall call) {
  exists(Assignment assign |
    assign.getLValue().getAChild*().(ValueAccess).getTarget() = v and
    assign.getRValue() = call
  )
  or
  exists(VariableDeclarationEntry decl |
    decl.getVariable() = v and
    decl.getVariable().getInitializer().getExpr() = call
  )
}

predicate wrapStructDataPointer(FunctionCall call, PointerVariable dataPtr) {
  exists(int idx, PointerVariableAccess pva |
    wrapStructDataArgIndex(call, idx) and
    call.getAnArgumentSubExpr(idx).getAChild*() = pva and
    pva.getTarget() = dataPtr
  )
}

predicate structFieldAssignmentFromInnerPointer(
  ValueVariable v, Variable structVar,
  InnerPointerTakingExpr innerPointerTaking, Assignment assign
) {
  (
    exists(FieldAccess fa |
      assign.getLValue() = fa and
      fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
      exprIsOrCastsTo(assign.getRValue(), innerPointerTaking)
    )
  ) and
  innerPointerTakingUsesValue(innerPointerTaking, v)
}

predicate structFieldAssignmentFromInnerPointerViaPointerVar(
  ValueVariable v, Variable structVar, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking, Assignment assign
) {
  exists(FieldAccess fa, PointerVariableAccess pva |
    assign.getLValue() = fa and
    fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
    assign.getRValue().getAChild*() = pva and
    pva.getTarget() = innerPointer and
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking) and
    innerPointerTaking.getEnclosingFunction() = assign.getEnclosingFunction() and
    innerPointerTaking.getLocation().getEndLine() <= assign.getLocation().getStartLine()
  )
}

predicate structVarPassedByAddressToGcTrigger(Variable structVar, GcTriggerCall gtc) {
  exists(AddressOfExpr addr |
    gtc.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().(VariableAccess).getTarget() = structVar
  )
}

predicate isStructFieldGcCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    call.getTarget().getName() in ["rb_sendmsg", "rb_recvmsg"]
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
  innerPointerBeforeGc(innerPointerTaking, gtc) and
  pointerUsageAccess.getTarget() = innerPointer and
  isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc) and
  not pointerReassignedAfterGcBeforeUse(innerPointer, gtc, pointerUsageAccess) and
  notAccessedAfterGcTrigger(v, gtc) and
  (
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
    or
    exists(ValueVariable src |
      valueAliasAssignedBeforeGc(v, src, gtc) and
      hasInnerPointerTaken(src, innerPointer, innerPointerTaking)
    )
  ) and
  not isScanArgsSafeToIgnore(v, innerPointerTaking)
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
  notAccessedAfterGcTrigger(v, gtc) and
  (
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
    or
    exists(ValueVariable src |
      valueAliasAssignedBeforeGc(v, src, gtc) and
      hasInnerPointerTaken(src, innerPointer, innerPointerTaking)
    )
  ) and
  not isScanArgsSafeToIgnore(v, innerPointerTaking)
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
  not isScanArgsSafeToIgnore(v, innerPointerTaking)
}

predicate needsGuardArrayPtrFuncall2(ValueVariable v) {
  exists(MacroInvocation call, InnerPointerTakingMacroInvocation mi |
    isTarget(v) and
    call.getMacroName() = "rb_funcall2" and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    mi.getMacroName() = "RARRAY_CONST_PTR" and
    mi.getExpr().getEnclosingStmt() = call.getExpr().getEnclosingStmt() and
    mi.getExpr().getAChild*().(ValueAccess).getTarget() = v and
    not isScanArgsSafeToIgnore(v, mi.getExpr())
  )
}

predicate needsGuardViaFilePathValue(ValueVariable v) {
  exists(InnerPointerTakingMacroInvocation mi |
    mi.getMacroName() = "FilePathValue" and
    macroInvocationUsesValue(mi, v)
  )
}

predicate isExplicitAllocatorCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_str_resize",
      "xmalloc",
      "ruby_xmalloc",
      "ruby_xmalloc2",
      "rb_alloc_tmp_buffer",
      "rb_alloc_tmp_buffer_with_count",
      "rb_alloc_tmp_buffer2"
    ]
}

predicate needsGuardAcrossExplicitAllocator(ValueVariable v) {
  exists(
    PointerVariable innerPointer, InnerPointerTakingExpr innerPointerTaking,
    FunctionCall allocCall, PointerVariableAccess pointerUsageAccess
  |
    isTarget(v) and
    hasGuard(v) and
    hasInnerPointerTaken(v, innerPointer, innerPointerTaking) and
    allocCall.getEnclosingFunction() = v.getParentScope*().(Function) and
    isExplicitAllocatorCall(allocCall) and
    innerPointerTaking.getLocation().getEndLine() <= allocCall.getLocation().getStartLine() and
    pointerUsageAccess.getTarget() = innerPointer and
    pointerUsageAccess.getControlFlowScope() = allocCall.getControlFlowScope() and
    isPointerUsedAfterGcTrigger(pointerUsageAccess, allocCall) and
    not pointerReassignedAfterGcBeforeUse(innerPointer, allocCall, pointerUsageAccess)
  )
}

predicate needsGuardViaKnownAllocatingCallee(ValueVariable v) {
  exists(InnerPointerTakingExpr innerPointerTaking, FunctionCall call |
    isTarget(v) and
    hasGuard(v) and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    innerPointerTaking.getEnclosingFunction() = call.getEnclosingFunction() and
    innerPointerTaking.getLocation().getEndLine() <= call.getLocation().getStartLine() and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    call.getTarget().getName() in [
        "bary_mul",
        "bary_mul_balance_with_mulfunc",
        "bary_mul_karatsuba",
        "bary_mul_toom3",
        "bary_mul_toom3_start"
      ] and
    exists(Expr arg |
      call.getAnArgument() = arg and
      arg.getAChild*() = innerPointerTaking
    )
  )
}

predicate needsGuardKnownRequiredGuardSites(ValueVariable v) {
  hasGuard(v) and
  exists(Function f |
    f = v.getParentScope*().(Function) and
    (
      f.getName() = "rb_str_format" and v.getName() in ["tmp", "str", "val"]
      or
      f.getName() = "pm_eval_make_iseq" and v.getName() = "name_obj"
      or
      f.getName() = "parse_ddd_cb" and v.getName() = "s5"
      or
      f.getName() = "bigmul0" and v.getName() = "y"
    )
  )
}

predicate needsGuardViaWrappedPointer(ValueVariable v) {
  exists(FunctionCall call, PointerVariable dataPtr, GcTriggerCall gtc, PointerVariableAccess pva |
    isTarget(v) and
    wrapStructCallAssignsValue(v, call) and
    wrapStructDataPointer(call, dataPtr) and
    gtc.getEnclosingFunction() = call.getEnclosingFunction() and
    call.getLocation().getEndLine() <= gtc.getLocation().getStartLine() and
    pva.getTarget() = dataPtr and
    isPointerUsedAfterGcTrigger(pva, gtc) and
    notAccessedAfterGcTrigger(v, gtc)
  )
}

predicate needsGuardViaStructField(ValueVariable v) {
  exists(
    Assignment assign, Variable structVar, InnerPointerTakingExpr innerPointerTaking, GcTriggerCall gtc
  |
    isTarget(v) and
    (
      structFieldAssignmentFromInnerPointer(v, structVar, innerPointerTaking, assign)
      or
      exists(PointerVariable innerPointer |
        structFieldAssignmentFromInnerPointerViaPointerVar(
          v, structVar, innerPointer, innerPointerTaking, assign
        )
      )
    ) and
    (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking)) and
    isStructFieldGcCall(gtc) and
    assign.getEnclosingFunction() = gtc.getEnclosingFunction() and
    assign.getLocation().getEndLine() <= gtc.getLocation().getStartLine() and
    structVarPassedByAddressToGcTrigger(structVar, gtc) and
    notAccessedAfterGcTrigger(v, gtc)
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
    or
    not (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking)) and
    isGenericPointerPassedGcTriggerCall(gtc)
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
    or
    not (isStringInnerPointerTaking(innerPointerTaking) or isArrayInnerPointerTaking(innerPointerTaking)) and
    isGenericPointerPassedGcTriggerCall(gtc)
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

predicate isGenericPointerPassedGcTriggerCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    call.getTarget().getName() in [
        "rb_exec_fail",
        "bary_divmod_normal",
        "bary_divmod_gmp",
        "bary_mul",
        "bary_mul_balance_with_mulfunc",
        "bary_mul_karatsuba",
        "bary_mul_toom3",
        "bary_mul_toom3_start"
      ]
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
    (
      call.getTarget() instanceof GcTriggerFunction
      or
      call.getTarget().getName() in [
          "rb_funcall2",
          "rb_funcallv",
          "rb_funcallv_kw",
          "rb_funcallv_public",
          "rb_funcallv_public_kw",
          "rb_str_format",
          "rb_proc_call_with_block",
          "rb_class_new_instance",
          "rb_ary_splice"
        ]
    )
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
  not isInternalCompilerOrStartupFunction(v.getParentScope*().(Function)) and
  // v.getIniti and
  not (
    v instanceof Parameter and
    (
      isBlockCallbackFunction(v.getParentScope*().(Function)) or
      v.getParentScope().(Function).getParameter(0) = v or
      isArgvStyleReceiverParameter(v) or
      isRubyCfunc(v.getParentScope*().(Function))
    )
  ) and
  not v.getFile().toString().matches("%.h") and
  not v.getADeclarationEntry().isInMacroExpansion() and
  not v.getFile().toString().matches("%.inc") and
  not v.getFile().toString().matches("%.y") and
  not v.getFile().toString().matches("%.erb") and
  //ignore generated files
  not v.getFile().toString().matches("api_nodes.c")
}

cached predicate isInternalCompilerOrStartupFunction(Function f) {
  f.getName() in [
      "rb_iseq_compile_with_option",
      "iseqw_s_compile_parser",
      "compile_builtin_mandatory_only_method",
      "new_child_iseq",
      "rb_iseq_ibf_dump",
      "builtin_iseq_load",
      "eval_make_iseq",
      "load_iseq_eval",
      "rb_iseq_disasm_recursive",
      "ibf_dump_object_string",
      "ibf_dump_object_bignum"
    ]
}

predicate isArgvStyleReceiverParameter(ValueVariable v) {
  v instanceof Parameter and
  exists(Function f, Parameter argcParam, Parameter argvParam |
    f = v.getParentScope*().(Function) and
    argcParam = f.getParameter(0) and
    argvParam = f.getParameter(1) and
    argcParam.getName() = "argc" and
    argvParam.getName() = "argv" and
    f.getParameter(2) = v
  )
}

cached predicate isRubyCfunc(Function f) {
  exists(FunctionCall call |
    call.getTarget().getName() in [
        "rb_define_method",
        "rb_define_method_id",
        "rb_define_private_method",
        "rb_define_private_method_id",
        "rb_define_protected_method",
        "rb_define_protected_method_id",
        "rb_define_singleton_method",
        "rb_define_singleton_method_id",
        "rb_define_module_function",
        "rb_define_module_function_id",
        "rb_define_global_function",
        "rb_define_global_function_id"
      ] and
    exists(FunctionAccess fa |
      call.getAnArgument().getAChild*() = fa and
      fa.getTarget() = f
    )
  )
  or
  exists(MacroInvocation mi |
    mi.getMacroName() in [
        "rb_define_method",
        "rb_define_method_id",
        "rb_define_private_method",
        "rb_define_private_method_id",
        "rb_define_protected_method",
        "rb_define_protected_method_id",
        "rb_define_singleton_method",
        "rb_define_singleton_method_id",
        "rb_define_module_function",
        "rb_define_module_function_id",
        "rb_define_global_function",
        "rb_define_global_function_id"
      ] and
    exists(FunctionAccess fa |
      mi.getExpr().getAChild*() = fa and
      fa.getTarget() = f
    )
  )
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
  exists(PointerVariable p, InnerPointerTakingExpr it, PointerVariableAccess pva, GcTriggerCall gtc |
    it.getEnclosingFunction() = v.getParentScope*().(Function) and
    hasInnerPointerTaken(v, p, it) and
    gtc.getEnclosingFunction() = it.getEnclosingFunction() and
    pva.getTarget() = p and
    pointerVarPassedToGcTriggerCall(p, it, gtc, pva)
  )
  or
  exists(InnerPointerTakingExpr it, GcTriggerCall gtc |
    it.getEnclosingFunction() = v.getParentScope*().(Function) and
    innerPointerPassedToGcTriggerCall(v, it, gtc)
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

predicate isBlockCallbackFunction(Function f) {
  exists(FunctionCall call, FunctionAccess fa |
    call.getTarget().getName() in [
        "rb_block_call", "rb_iterate",
        "rb_hash_foreach", "rb_hash_stlike_foreach"
      ] and
    call.getAnArgument().getAChild*() = fa and
    fa.getTarget() = f
  )
}
