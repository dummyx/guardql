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
      isNoGvlFunction(call.getTarget()) or
      isGcTrigger(call.getTarget())
    )
  )
}

predicate isStrongGcTriggerName(string name) {
  name in ["gc_enter", "rb_enc_sprintf", "rb_str_catf", "rb_str_cat_cstr"]
}

predicate isStrongGcTrigger(Function function) {
  isStrongGcTriggerName(function.getName())
  or
  isNoGvlFunction(function)
  or
  exists(FunctionCall call |
    call.getEnclosingFunction() = function and
    (
      isStrongGcTriggerName(call.getTarget().getName()) or
      isNoGvlFunction(call.getTarget()) or
      isStrongGcTrigger(call.getTarget())
    )
  )
}

predicate isAllocOrGcCall(FunctionCall call) {
  call.getTarget().getName() in [
      "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store", "rb_hash_new", "rb_hash_aset",
      "rb_hash_lookup2", "rb_obj_alloc", "rb_class_new_instance", "rb_imemo_new", "ALLOC",
      "ALLOC_N", "REALLOC_N"
    ]
  or
  isRubyCallbackTrigger(call.getTarget())
}

predicate isMemoryAllocCall(Call call) {
  call.getTarget().getName() in [
      "malloc", "calloc", "realloc", "reallocarray",
      "xmalloc", "xcalloc", "xrealloc", "xmalloc2", "xrealloc2",
      "ruby_xmalloc", "ruby_xcalloc", "ruby_xrealloc", "ruby_xmalloc2", "ruby_xrealloc2",
      "rb_xmalloc", "rb_xcalloc", "rb_xrealloc", "rb_xmalloc_mul_add", "rb_xmalloc_mul_add_mul",
      "ALLOC", "ALLOC_N", "REALLOC_N", "ZALLOC", "ALLOCV", "ALLOCV_N",
      "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
      "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store", "rb_hash_new", "rb_hash_aset",
      "rb_hash_lookup2", "rb_obj_alloc", "rb_class_new_instance", "rb_imemo_new"
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

predicate isPointerEscapeFunction(Function function, int idx) {
  function.getName() in ["pm_string_constant_init", "pm_string_shared_init", "pm_string_owned_init"] and
  idx = 1
  or
  exists(FunctionCall call |
    call.getEnclosingFunction() = function and
    call.getTarget().getName() in [
        "pm_string_constant_init", "pm_string_shared_init", "pm_string_owned_init"
      ] and
    call.getAnArgumentSubExpr(1).getAChild*().(VariableAccess).getTarget() =
      function.getParameter(idx)
  )
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

predicate callArgumentMatches(Call call, Expr target) {
  exists(Expr arg |
    call.getAnArgument() = arg and
    exprIsOrCastsTo(arg, target)
  )
}

predicate callArgumentOffsetMatches(Call call, Expr target) {
  exists(AddExpr add |
    call.getAnArgument() = add and
    (
      exprIsOrCastsTo(add.getLeftOperand(), target) or
      exprIsOrCastsTo(add.getRightOperand(), target)
    )
  )
  or
  exists(SubExpr sub |
    call.getAnArgument() = sub and
    exprIsOrCastsTo(sub.getLeftOperand(), target)
  )
}

predicate callArgumentSubExprMatches(FunctionCall call, int idx, Expr target) {
  exprIsOrCastsTo(call.getAnArgumentSubExpr(idx), target)
}

predicate callArgumentSubExprOffsetMatches(FunctionCall call, int idx, Expr target) {
  exists(AddExpr add |
    add = call.getAnArgumentSubExpr(idx) and
    (
      exprIsOrCastsTo(add.getLeftOperand(), target) or
      exprIsOrCastsTo(add.getRightOperand(), target)
    )
  )
  or
  exists(SubExpr sub |
    sub = call.getAnArgumentSubExpr(idx) and
    exprIsOrCastsTo(sub.getLeftOperand(), target)
  )
}

predicate isValueOrCharPointerType(Type t) {
  exists(PointerType pt |
    pt = t and
    (
      pt.getBaseType().getName().matches("%char%")
    )
  )
}

predicate isTrackedInnerPointer(InnerPointerTakingExpr innerPointerTaking) {
  exists(Type t | t = innerPointerTaking.getType() and isValueOrCharPointerType(t))
}

predicate innerPointerTakingRelatedToValue(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  isTrackedInnerPointer(innerPointerTaking) and
  innerPointerTakingUsesValue(innerPointerTaking, v) and
  not exists(Assignment assign | assign.getLValue() = innerPointerTaking) and
  not exists(CrementOperation crement | crement.getOperand() = innerPointerTaking)
}

predicate innerPointerTakingRelatedToValueAny(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  innerPointerTakingUsesValue(innerPointerTaking, v) and
  not exists(Assignment assign | assign.getLValue() = innerPointerTaking) and
  not exists(CrementOperation crement | crement.getOperand() = innerPointerTaking)
}

predicate guardLikelyNeeded(ValueVariable v) {
  exists(InnerPointerTakingExpr innerPointerTaking |
    innerPointerTakingRelatedToValueAny(v, innerPointerTaking)
  )
  or
  exists(GcTriggerCall gtc, ValueAccess va |
    va.getTarget() = v and
    gtc.getAnArgument().getAChild*() = va and
    notAccessedAfterCall(v, gtc)
  )
  or
  exists(int lastLine, GcTriggerCall gtc |
    lastValueLine(v, lastLine) and
    gtc.getEnclosingFunction() = v.getParentScope*().(Function) and
    gtc.getLocation().getStartLine() >= lastLine
  )
  or
  exists(int lastLine, ExprCall call |
    lastValueLine(v, lastLine) and
    call.getEnclosingFunction() = v.getParentScope*().(Function) and
    call.getLocation().getStartLine() >= lastLine and
    not exists(FunctionAccess fa | call.getExpr().getAChild*() = fa)
  )
}

predicate innerPointerBeforeGc(InnerPointerTakingExpr innerPointerTaking, GcTriggerCall gtc) {
  innerPointerTaking.getEnclosingFunction() = gtc.getEnclosingFunction() and
  (
    innerPointerTaking.getLocation().getEndLine() <= gtc.getLocation().getStartLine() or
    innerPointerTaking.getEnclosingStmt() = gtc.getEnclosingStmt()
  )
}

predicate lastRelevantValueAccessLine(ValueVariable v, int line) {
  line =
    max(int l |
      exists(ValueAccess va |
        va.getTarget() = v and
        not isGuardAccess(va) and
        not isNoreturnAccess(va) and
        l = va.getLocation().getStartLine()
      )
    | l)
}

predicate lastValueLine(ValueVariable v, int line) {
  line =
    max(int l |
      (
        exists(ValueAccess va |
          va.getTarget() = v and
          not isGuardAccess(va) and
          not isNoreturnAccess(va) and
          l = va.getLocation().getStartLine()
        )
        or
        exists(Assignment assign |
          assign.getLValue().(ValueAccess).getTarget() = v and
          l = assign.getLocation().getStartLine()
        )
        or
        exists(VariableDeclarationEntry decl |
          decl.getVariable() = v and
          l = decl.getLocation().getStartLine()
        )
        or
        exists(Parameter p |
          p = v and
          l = p.getLocation().getStartLine()
        )
      )
    | l)
}

predicate pointerDefinedFromInnerPointer(
  ValueVariable v, PointerVariable innerPointer, InnerPointerTakingExpr innerPointerTaking, int defLine
) {
  exists(Assignment assign |
    assign.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    assign.getLValue().(VariableAccess).getTarget() = innerPointer and
    exprIsOrCastsTo(assign.getRValue(), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    defLine = assign.getLocation().getStartLine()
  )
  or
  exists(VariableDeclarationEntry decl |
    decl.getVariable() = innerPointer and
    decl.getVariable().getParentScope*().(Function) = innerPointerTaking.getEnclosingFunction() and
    exprIsOrCastsTo(decl.getVariable().getInitializer().getExpr(), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    defLine = decl.getLocation().getStartLine()
  )
}

predicate earliestGcTriggerLineAfter(InnerPointerTakingExpr innerPointerTaking, int line) {
  line =
    min(int l |
      exists(GcTriggerCall gtc |
        gtc.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
        l = gtc.getLocation().getStartLine() and
        l >= innerPointerTaking.getLocation().getEndLine()
      )
    | l)
}

pragma[inline]
predicate needsGuard(ValueVariable v) {
  exists(InnerPointerTakingExpr innerPointerTaking |
    innerPointerTakingRelatedToValue(v, innerPointerTaking) and
    not scanArgsSafeAt(v, innerPointerTaking) and
    (
      exists(GcTriggerCall gtc |
        innerPointerBeforeGc(innerPointerTaking, gtc) and
        isDirectStrongGcTriggerCall(gtc) and
        (
          pointerPassedToGcTriggerCall(v, gtc, innerPointerTaking)
        )
        and
        exists(int lastLine |
          lastRelevantValueAccessLine(v, lastLine) and
          lastLine <= gtc.getLocation().getEndLine()
        )
      )
      or
      exists(GcTriggerCall gtc, PointerVariable innerPointer, PointerVariableAccess use, int defLine |
        innerPointerBeforeGc(innerPointerTaking, gtc) and
        isStrongGcTriggerCall(gtc) and
        pointerDefinedFromInnerPointer(v, innerPointer, innerPointerTaking, defLine) and
        defLine <= gtc.getLocation().getStartLine() and
        use.getTarget() = innerPointer and
        use.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
        use.getLocation().getStartLine() > gtc.getLocation().getEndLine() and
        dominates(gtc, use) and
        exists(int lastLine |
          lastRelevantValueAccessLine(v, lastLine) and
          lastLine <= gtc.getLocation().getEndLine()
        ) and
        not exists(Assignment reassign |
          reassign.getLValue().(VariableAccess).getTarget() = innerPointer and
          reassign.getLocation().getStartLine() > defLine and
          reassign.getLocation().getStartLine() < use.getLocation().getStartLine()
        )
      )
      or
      exists(FunctionCall call, int idx |
        call.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
        (
      (
        (callArgumentSubExprMatches(call, idx, innerPointerTaking) or
          callArgumentSubExprOffsetMatches(call, idx, innerPointerTaking)) and
        innerPointerTakingUsesValue(innerPointerTaking, v)
      )
      or
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        innerPointerTaking.getLocation().getEndLine() <= call.getLocation().getStartLine() and
        exists(PointerVariableAccess pva |
          pva.getTarget() = innerPointer and
          (callArgumentSubExprMatches(call, idx, pva) or
            callArgumentSubExprOffsetMatches(call, idx, pva))
        )
      )
        ) and
        paramUsedAfterGcTrigger(call.getTarget(), idx) and
        exists(int lastLine |
          lastRelevantValueAccessLine(v, lastLine) and
          lastLine <= call.getLocation().getEndLine()
        )
      )
    )
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

predicate isStrongGcTriggerCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    isStrongGcTrigger(call.getTarget())
  )
  or
  exists(ExprCall call, FunctionAccess fa |
    call = gtc and
    call.getExpr().getAChild*() = fa and
    isStrongGcTrigger(fa.getTarget())
  )
}

predicate isDirectStrongGcTriggerCall(GcTriggerCall gtc) {
  exists(FunctionCall call |
    call = gtc and
    isStrongGcTriggerName(call.getTarget().getName())
  )
  or
  exists(ExprCall call, FunctionAccess fa |
    call = gtc and
    call.getExpr().getAChild*() = fa and
    isStrongGcTriggerName(fa.getTarget().getName())
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

predicate valueOverwrittenByObjectGeneratingCall(ValueVariable v, ControlFlowNode changeNode) {
  exists(Assignment assign, FunctionCall call |
    changeNode = assign and
    assign.getLValue().(ValueAccess).getTarget() = v and
    assign.getRValue() = call and
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
    scanCall.getLocation().getEndLine() <= va.getLocation().getStartLine() and
    not exists(ControlFlowNode change |
      valueOverwrittenByObjectGeneratingCall(va.getTarget(), change) and
      scanCall.getLocation().getEndLine() <= change.getLocation().getStartLine() and
      change.getLocation().getEndLine() <= va.getLocation().getStartLine()
    )
  )
}

predicate scanArgsSafeAt(ValueVariable v, InnerPointerTakingExpr innerPointerTaking) {
  exists(InnerPointerTakingFunctionByNameCall fc, ValueAccess baseAccess |
    fc = innerPointerTaking and
    baseAccess.getTarget() = v and
    fc.getAnArgument().getAChild*() = baseAccess and
    isScanArgsDerivedValue(baseAccess)
  )
}

predicate notAccessedAfterCall(ValueVariable v, Call call) {
  not exists(VariableAccess va |
    va.getTarget() = v and
    va = call.getASuccessor+() and
    not isGuardAccess(va) and
    not isNoreturnAccess(va)
  )
}

predicate calleeParamUsedAfterGcTrigger(
  Function callee, int idx, GcTriggerCall gtc, PointerVariableAccess paramUse
) {
  gtc.getEnclosingFunction() = callee and
  paramUse.getTarget() = callee.getParameter(idx) and
  paramUse.getLocation().getStartLine() > gtc.getLocation().getEndLine() and
  (
    isStrongGcTriggerCall(gtc) or
    isStrongGcTrigger(callee)
  )
}

predicate paramUsedAfterGcTrigger(Function callee, int idx) {
  exists(GcTriggerCall gtc, PointerVariableAccess paramUse |
    calleeParamUsedAfterGcTrigger(callee, idx, gtc, paramUse)
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

predicate hasDerivedPointerDirect(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  hasInnerPointerTaken(v, innerPointer, innerPointerTaking)
  or
  hasTypedDataOutParamPointer(v, innerPointer, innerPointerTaking)
}

predicate pointerAliasedFromAfter(
  PointerVariable source, PointerVariable alias, InnerPointerTakingExpr innerPointerTaking
) {
  exists(Assignment assign |
    assign.getLValue().(VariableAccess).getTarget() = alias and
    assign.getRValue().getAChild*().(PointerVariableAccess).getTarget() = source and
    assign.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    assign.getLocation().getStartLine() >= innerPointerTaking.getLocation().getEndLine()
  )
  or
  exists(VariableDeclarationEntry decl |
    decl.getVariable() = alias and
    decl.getVariable().getInitializer().getExpr().getAChild*().(PointerVariableAccess).getTarget() =
      source and
    decl.getVariable().getParentScope*().(Function) = innerPointerTaking.getEnclosingFunction() and
    decl.getLocation().getStartLine() >= innerPointerTaking.getLocation().getEndLine()
  )
}

predicate hasDerivedPointer(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  hasDerivedPointerDirect(v, innerPointer, innerPointerTaking)
  or
  exists(PointerVariable source |
    hasDerivedPointerDirect(v, source, innerPointerTaking) and
    pointerAliasedFromAfter(source, innerPointer, innerPointerTaking)
  )
}

predicate interproceduralPointerUseAfterGc(
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(FunctionCall call, Function callee, int idx, PointerVariableAccess paramUse |
    call.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    callee = call.getTarget() and
    (
      // Directly pass the inner-pointer expression as an argument.
      (
        call.getAnArgumentSubExpr(idx).getAChild*() = innerPointerTaking and
        innerPointerTakingUsesValue(innerPointerTaking, v)
      )
      or
      // Pass a derived pointer variable as an argument.
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        innerPointerTaking.getLocation().getEndLine() <= call.getLocation().getStartLine() and
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
  InnerPointerTakingExpr innerPointerTaking
) {
  (
    gtc.getControlFlowScope() = v.getParentScope*().(Function) and
    gtc.getControlFlowScope() = innerPointerTaking.getControlFlowScope()
  ) and
  isStrongGcTriggerCall(gtc) and
  innerPointerBeforeGc(innerPointerTaking, gtc) and
  (
    exists(PointerVariable innerPointer |
      innerPointer != v and
      pointerUsageAccess.(PointerVariableAccess).getTarget() = innerPointer and
      hasDerivedPointer(v, innerPointer, innerPointerTaking) and
      isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc)
    )
    or
    (
      pointerUsageAccess = innerPointerTaking and
      innerPointerTakingUsesValue(innerPointerTaking, v) and
      isPointerUsedAfterGcTrigger(pointerUsageAccess, gtc)
    )
  ) and
  notAccessedAfterGcTrigger(v, gtc)
}

predicate pointerStoredInStructPassedToCall(PointerVariable innerPointer, Call call) {
  exists(Variable structVar, FieldAccess fa, Assignment assign, AddressOfExpr addr |
    assign.getRValue().(PointerVariableAccess).getTarget() = innerPointer and
    assign.getLValue().getAChild*() = fa and
    fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().getAChild*().(VariableAccess).getTarget() = structVar and
    assign.getLocation().getEndLine() <= call.getLocation().getStartLine() and
    assign.getEnclosingFunction() = call.getEnclosingFunction()
  )
}

predicate inlinePointerStoredInStructPassedToCall(
  ValueVariable v, InnerPointerTakingExpr innerPointerTaking, Call call
) {
  exists(Variable structVar, FieldAccess fa, Assignment assign, AddressOfExpr addr |
    assign.getRValue() = innerPointerTaking and
    innerPointerTakingUsesValue(innerPointerTaking, v) and
    assign.getLValue().getAChild*() = fa and
    fa.getQualifier().getAChild*().(VariableAccess).getTarget() = structVar and
    call.getAnArgument().getAChild*() = addr and
    addr.getAnOperand().getAChild*().(VariableAccess).getTarget() = structVar and
    assign.getLocation().getEndLine() <= call.getLocation().getStartLine() and
    assign.getEnclosingFunction() = call.getEnclosingFunction()
  )
}

predicate pointerPassedToGcTriggerCall(
  ValueVariable v, GcTriggerCall gtc,
  InnerPointerTakingExpr innerPointerTaking
) {
  (
    (
      innerPointerBeforeGc(innerPointerTaking, gtc)
    )
    or
    callArgumentMatches(gtc, innerPointerTaking)
  ) and
  (
    (callArgumentMatches(gtc, innerPointerTaking) or callArgumentOffsetMatches(gtc, innerPointerTaking)) and
    innerPointerTakingUsesValue(innerPointerTaking, v)
    or
    inlinePointerStoredInStructPassedToCall(v, innerPointerTaking, gtc)
    or
    exists(PointerVariable innerPointer |
      hasDerivedPointer(v, innerPointer, innerPointerTaking) and
      (
        exists(PointerVariableAccess pva |
          pva.getTarget() = innerPointer and
          (callArgumentMatches(gtc, pva) or callArgumentOffsetMatches(gtc, pva))
        )
        or
        pointerStoredInStructPassedToCall(innerPointer, gtc)
      )
    )
  )
}

predicate pointerEscapesToCall(
  ValueVariable v, FunctionCall escapeCall,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(int idx |
    isPointerEscapeFunction(escapeCall.getTarget(), idx) and
    (
      (callArgumentSubExprMatches(escapeCall, idx, innerPointerTaking) or
        callArgumentSubExprOffsetMatches(escapeCall, idx, innerPointerTaking)) and
      innerPointerTakingUsesValue(innerPointerTaking, v)
      or
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        innerPointerTaking.getLocation().getEndLine() <= escapeCall.getLocation().getStartLine() and
        innerPointerTaking.getEnclosingFunction() = escapeCall.getEnclosingFunction() and
        exists(PointerVariableAccess pva |
          pva.getTarget() = innerPointer and
          (callArgumentSubExprMatches(escapeCall, idx, pva) or
            callArgumentSubExprOffsetMatches(escapeCall, idx, pva))
        )
      )
    )
  )
}

predicate pointerReturnedAfterGc(
  ValueVariable v, GcTriggerCall gtc, InnerPointerTakingExpr innerPointerTaking
) {
  innerPointerTaking.getEnclosingFunction().getType() instanceof PointerType and
  isStrongGcTriggerCall(gtc) and
  innerPointerBeforeGc(innerPointerTaking, gtc) and
  exists(ReturnStmt ret |
    ret.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    gtc.getLocation().getEndLine() < ret.getLocation().getStartLine() and
    ret.getExpr().getType() instanceof PointerType and
    (
      exprIsOrCastsTo(ret.getExpr(), innerPointerTaking) and
      innerPointerTakingUsesValue(innerPointerTaking, v)
      or
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        exists(PointerVariableAccess pva |
          pva.getTarget() = innerPointer and
          exprIsOrCastsTo(ret.getExpr(), pva)
        )
      )
    )
  )
}

predicate pointerReturned(
  ValueVariable v, InnerPointerTakingExpr innerPointerTaking
) {
  innerPointerTaking.getEnclosingFunction().getType() instanceof PointerType and
  exists(ReturnStmt ret |
    ret.getEnclosingFunction() = innerPointerTaking.getEnclosingFunction() and
    (
      innerPointerTaking.getLocation().getEndLine() <= ret.getLocation().getStartLine() or
      innerPointerTaking.getEnclosingStmt() = ret.getEnclosingStmt()
    ) and
    (
      exprIsOrCastsTo(ret.getExpr(), innerPointerTaking) and
      innerPointerTakingUsesValue(innerPointerTaking, v)
      or
      exists(PointerVariable innerPointer |
        hasDerivedPointer(v, innerPointer, innerPointerTaking) and
        exists(PointerVariableAccess pva |
          pva.getTarget() = innerPointer and
          exprIsOrCastsTo(ret.getExpr(), pva)
        )
      )
    )
  )
}

predicate macroInvocationHasGcTrigger(MacroInvocation mi) {
  exists(GcTriggerCall gtc |
    mi.getAnExpandedElement() = gtc and
    isDirectStrongGcTriggerCall(gtc)
  )
}

pragma[inline]
predicate needsGuard(
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingExpr innerPointerTaking
) {
  innerPointerTaking.getEnclosingFunction() = v.getParentScope*().(Function) and
  innerPointerTakingRelatedToValue(v, innerPointerTaking) and
  isTarget(v) and
  not scanArgsSafeAt(v, innerPointerTaking) and
  (
    intraProceduralPointerUseAfterGc(v, gtc, pointerUsageAccess, innerPointerTaking)
    or
    interproceduralPointerUseAfterGc(v, gtc, pointerUsageAccess, innerPointerTaking)
    or
    (
      pointerPassedToGcTriggerCall(v, gtc, innerPointerTaking) and
      pointerUsageAccess = innerPointerTaking
    )
    or
    exists(FunctionCall escapeCall |
      pointerEscapesToCall(v, escapeCall, innerPointerTaking) and
      gtc.getControlFlowScope() = escapeCall.getControlFlowScope() and
      escapeCall.getLocation().getEndLine() <= gtc.getLocation().getStartLine() and
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

predicate isGuardCandidate(ValueVariable v) { isTarget(v) and not isSelfParameter(v) }
