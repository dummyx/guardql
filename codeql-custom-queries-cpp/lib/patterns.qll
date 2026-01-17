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
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  exists(Assignment assignment |
    assignment.getLValue().getAChild*().(VariableAccess).getTarget() = innerPointer and
    assignment.getRValue().getAChild*() = innerPointerTaking and
    innerPointerTaking.getAnArgument().(ValueAccess).getTarget() = v
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
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  (
    innerPointerTaking.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
    or
    innerPointerTaking.getAnArgument().getAChild*().(FieldAccess).getQualifier() = v.getAnAccess()
  ) and
  innerPointerTaking.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() = innerPointer
}

/**
 * Checks if any of the inner pointer patterns exist for the given variables.
 */
predicate hasInnerPointerTaken(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  hasInnerPointerAssignment(v, innerPointer, innerPointerTaking)
  or
  hasInnerPointerFunctionCall(v, innerPointer, innerPointerTaking)
}

/**
 * Checks if a pointer variable is used after a GC trigger call.
 * The usage can be either a direct successor or a successor of the enclosing block.
 */
predicate isPointerUsedAfterGcTrigger(
  PointerVariableAccess pointerUsageAccess, GcTriggerCall gcTriggerCall
) {
  gcTriggerCall.getASuccessor+() = pointerUsageAccess
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
    va.getTarget() = v and va = gcTriggerCall.getASuccessor+() and not isGuardAccess(va)
  )
}
