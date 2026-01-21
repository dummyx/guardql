import guard_checker
import types
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
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
    assignment.getRValue() = innerPointerTaking and
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
    innerPointer.getInitializer().getExpr() = innerPointerTaking and
    innerPointerTakingUsesValue(innerPointerTaking, v)
  )
}

predicate macroInvocationUsesValue(InnerPointerTakingMacroInvocation mi, ValueVariable v) {
  mi.getEnclosingFunction() = v.getParentScope*().(Function) and
  mi.getUnexpandedArgument(0).regexpMatch(".*\\b" + v.getName() + "\\b.*")
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
}

/**
 * Checks if a usage node is after a GC trigger call.
 * The usage can be either a direct successor or a successor of the enclosing block.
 */
predicate isPointerUsedAfterGcTrigger(ControlFlowNode usageNode, GcTriggerCall gcTriggerCall) {
  usageNode.getControlFlowScope() = gcTriggerCall.getControlFlowScope() and
  (
    usageNode.getLocation().getStartLine() > gcTriggerCall.getLocation().getEndLine()
    or
    (
      usageNode.getLocation().getStartLine() = gcTriggerCall.getLocation().getStartLine() and
      usageNode.getLocation().getStartColumn() >= gcTriggerCall.getLocation().getEndColumn()
    )
  )
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

predicate isArgumentToGcTriggerCall(ValueAccess va, GcTriggerCall afterCall) {
  exists(GcTriggerCall call |
    call.getControlFlowScope() = afterCall.getControlFlowScope() and
    call.getLocation().getStartLine() > afterCall.getLocation().getEndLine() and
    call.getAnArgument().getAChild*() = va
  )
}

predicate notAccessedAfterGcTrigger(ValueVariable v, GcTriggerCall gcTriggerCall) {
  not exists(VariableAccess va |
    va.getTarget() = v and
    va.getControlFlowScope() = gcTriggerCall.getControlFlowScope() and
    va.getLocation().getStartLine() > gcTriggerCall.getLocation().getEndLine() and
    not isGuardAccess(va) and
    not isNoreturnAccess(va) and
    not isArgumentToGcTriggerCall(va, gcTriggerCall)
  )
}
