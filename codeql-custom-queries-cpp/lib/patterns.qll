import guard_checker
import types
import cpp
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

/**
 * Checks if there's an assignment where the RValue involves an InnerPointerTakingFunctionByNameCall
 * that takes the given ValueVariable as an argument, and assigns to the given PointerVariable.
 * ```
 * VALUE a;
 * ptr* b;
 * b = inner_pointer_taking_function(a);
 * ```
 */
predicate hasInnerPointerAssignment(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(Assignment assignment |
    assignment.getLValue().(VariableAccess).getTarget() = innerPointer and
    exprIsOrCastsTo(assignment.getRValue(), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v)
  )
}

/**
 * Checks if there's a declaration of a PointerVariable initialized with an InnerPointerTakingExpr
 * that uses the given ValueVariable as an argument.
 *
 * ```
 * VALUE a;
 * const VALUE *b = RARRAY_CONST_PTR(a);
 * ```
 */
predicate hasInnerPointerDeclaration(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(VariableDeclarationEntry declEntry |
    declEntry.getVariable() = innerPointer and
    exprIsOrCastsTo(innerPointer.getInitializer().getExpr(), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v)
  )
}

predicate macroInvocationUsesValue(InnerPointerTakingMacroInvocation mi, ValueVariable v) {
  mi.getEnclosingFunction() = v.getParentScope*().(Function) and
  (
    exists(ValueAccess va |
      mi.getExpr().getAChild*() = va and
      va.getTarget() = v
    )
    or
    mi.getUnexpandedArgument(0).regexpMatch(".*\\b" + v.getName() + "\\b.*")
  )
}

predicate hasInnerPointerMacroExpansionAssignment(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(InnerPointerTakingMacroInvocation mi, Assignment assign |
    mi.getMacroName() in ["RSTRING_GETMEM", "RB_IO_POINTER", "GetOpenFile", "Data_Get_Struct", "TypedData_Get_Struct"] and
    mi.getAnExpandedElement() = assign and
    assign.getLValue().(VariableAccess).getTarget() = innerPointer and
    exprIsOrCastsTo(assign.getRValue(), innerPointerTaking) and
    innerPointerTakingUsesValue(innerPointerTaking, v)
  )
}

predicate hasMacroOutParamByExpansion(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(InnerPointerTakingMacroInvocation mi, Assignment assign |
    mi.getMacroName() in ["RSTRING_GETMEM", "RB_IO_POINTER", "GetOpenFile", "Data_Get_Struct", "TypedData_Get_Struct"] and
    innerPointerTaking = mi.getExpr() and
    mi.getAnExpandedElement() = assign and
    assign.getLValue().(VariableAccess).getTarget() = innerPointer and
    macroInvocationUsesValue(mi, v)
  )
}

predicate innerPointerTakingUsesValue(InnerPointerTakingExpr innerPointerTaking, ValueVariable v) {
  exists(InnerPointerTakingFunctionByNameCall fc |
    fc = innerPointerTaking and
    fc.getAnArgument().(ValueAccess).getTarget() = v
  )
  or
  exists(FunctionCall fc |
    fc = innerPointerTaking and
    fc.getTarget() instanceof InnerPointerGetterFunction and
    fc.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
  )
  or
  exists(InnerPointerTakingMacroInvocation mi |
    innerPointerTaking = mi.getExpr() and
    macroInvocationUsesValue(mi, v)
  )
}

/**
 * Checks if there's an InnerPointerTakingFunctionByNameCall that takes both the ValueVariable
 * and the PointerVariable as arguments (directly or through field access).
 * ```
 * VALUE a;
 * ptr* b;
 * inner_pointer_taking_function(a, b);
 * ```
 */
predicate hasInnerPointerFunctionCall(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  exists(InnerPointerTakingFunctionByNameCall fc |
    fc = innerPointerTaking and
    (
      fc.getAnArgument().(ValueAccess).getTarget() = v
    ) and
    fc.getAnArgument().(PointerVariableAccess).getTarget() = innerPointer
  )
}

/**
 * Checks if any of the inner pointer patterns exist for the given variables.
 */
predicate hasInnerPointerTaken(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingExpr innerPointerTaking
) {
  hasInnerPointerAssignment(v, innerPointer, innerPointerTaking)
  or
  hasInnerPointerDeclaration(v, innerPointer, innerPointerTaking)
  or
  hasInnerPointerFunctionCall(v, innerPointer, innerPointerTaking)
  or
  hasInnerPointerMacroExpansionAssignment(v, innerPointer, innerPointerTaking)
  or
  hasMacroOutParamByExpansion(v, innerPointer, innerPointerTaking)
}

/**
 * Holds if `usageNode` is reachable *after* `gcTriggerCall` in the CFG.
 *
 * This avoids common false positives when `usageNode` is an argument expression
 * of `gcTriggerCall` (arguments are evaluated before the call).
 */
pragma[inline]
predicate isPointerUsedAfterGcTrigger(ControlFlowNode usageNode, GcTriggerCall gcTriggerCall) {
  usageNode.getControlFlowScope() = gcTriggerCall.getControlFlowScope() and
  gcTriggerCall.getASuccessor+() = usageNode
}

/*
 * predicate passedToGcTrigger(ValueVariable v, ValueAccess initVAccess, FunctionCall gcTriggerCall) {
 *  exists(int i |
 *    initVAccess = v.getAnAccess() and
 *    i < count(gcTriggerCall.getAnArgument()) and
 *    gcTriggerCall.getAnArgumentSubExpr(i) = v.getAnAccess() and
 *    isArgumentNotSafe(gcTriggerCall.getTarget(), i)
 *  )
 * }
 */

predicate notAccessedAfterGcTrigger(ValueVariable v, GcTriggerCall gcTriggerCall) {
  not exists(VariableAccess va |
    va.getTarget() = v and
    va.getControlFlowScope() = gcTriggerCall.getControlFlowScope() and
    isPointerUsedAfterGcTrigger(va, gcTriggerCall) and
    va.getLocation().getStartLine() > gcTriggerCall.getLocation().getEndLine() and
    not isGuardAccess(va) and
    isValuePassedToCallAfterGcTrigger(va, gcTriggerCall)
  )
}

predicate isValuePassedToCallAfterGcTrigger(ValueAccess va, GcTriggerCall afterCall) {
  exists(FunctionCall call |
    call.getControlFlowScope() = afterCall.getControlFlowScope() and
    call.getLocation().getStartLine() > afterCall.getLocation().getEndLine() and
    not isHoistableFunction(call.getTarget()) and
    exists(Expr arg | call.getAnArgument() = arg and exprIsOrCastsTo(arg, va))
  )
  or
  exists(ExprCall call |
    call.getControlFlowScope() = afterCall.getControlFlowScope() and
    call.getLocation().getStartLine() > afterCall.getLocation().getEndLine() and
    exists(Expr arg | call.getAnArgument() = arg and exprIsOrCastsTo(arg, va))
  )
}

predicate isHoistableFunction(Function function) {
  exists(Attribute attr |
    attr = function.getAnAttribute() and
    attr.hasName(["pure", "const"])
  )
}

/**
 * Holds if `p` is (re)assigned after `gcTriggerCall` on some path to `use`.
 *
 * This prevents false positives where a pointer variable is reused and
 * overwritten after the GC trigger (e.g., `GetOpenFile(x, fptr)` occurs again),
 * so the post-GC use does not actually refer to the pre-GC derived pointer.
 */
pragma[inline]
predicate pointerReassignedAfterGcBeforeUse(
  PointerVariable p, GcTriggerCall gcTriggerCall, PointerVariableAccess use
) {
  exists(Assignment assign |
    assign.getControlFlowScope() = gcTriggerCall.getControlFlowScope() and
    assign.getLValue().getAChild*().(VariableAccess).getTarget() = p and
    isPointerUsedAfterGcTrigger(assign, gcTriggerCall) and
    assign.getASuccessor*() = use
  )
}
