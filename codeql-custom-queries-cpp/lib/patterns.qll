import guard_checker
import types
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

/**
 * Checks if a ControlFlowNode represents an initial access to a ValueVariable.
 * This includes both direct variable access and variable declarations.
 */
predicate isInitialVariableAccess(ControlFlowNode node, ValueVariable v) {
  node.(ValueAccess).getTarget() = v
  or
  node.(Declaration).getADeclarationEntry().(VariableDeclarationEntry).getVariable() = v
}

/**
 * Checks if there's an assignment where the RValue involves an InnerPointerTakingFunctionByNameCall
 * that takes the given ValueVariable as an argument, and assigns to the given PointerVariable.
 * ```
 * VALUE a;
 * ptr* b;
 * b = inner_pointer_taking_function(a);
 * ```
 */
predicate hasInnerPointerAssignment(ValueVariable v, PointerVariable innerPointer) {
  exists(Assignment assignment |
    assignment.getLValue().getAChild*().(VariableAccess).getTarget() = innerPointer and
    assignment.getRValue().getAChild*() instanceof InnerPointerTakingFunctionByNameCall and
    assignment
        .getRValue()
        .getAChild*()
        .(InnerPointerTakingFunctionByNameCall)
        .getAnArgument()
        .(ValueAccess)
        .getTarget() = v
  )
}

/**
 * Checks if there's a declaration of a PointerVariable initialized with an InnerPointerTakingFunctionByNameCall
 * that takes the given ValueVariable as an argument.
 * 
 * ```
 * VALUE a;
 * ptr* b = inner_pointer_taking_function(a);
 * ```
 */
predicate hasInnerPointerDeclaration(ValueVariable v, PointerVariable innerPointer) {
  exists(
    Declaration decl, VariableDeclarationEntry declEntry,
    InnerPointerTakingFunctionByNameCall pointerTakingCall
  |
    decl.getADeclarationEntry() = declEntry and
    declEntry.getVariable() = innerPointer and
    innerPointer.getInitializer().getExpr() = pointerTakingCall and
    pointerTakingCall.getAnArgument().getAChild*().(ValueAccess).getTarget() = v
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
predicate hasInnerPointerFunctionCall(ValueVariable v, PointerVariable innerPointer) {
  exists(InnerPointerTakingFunctionByNameCall pointerTakingCall |
    (
      pointerTakingCall.getAnArgument().getAChild*().(ValueAccess).getTarget() = v or
      pointerTakingCall.getAnArgument().getAChild*().(FieldAccess).getQualifier() =
        v.getAnAccess()
    ) and
    pointerTakingCall.getAnArgument().getAChild*().(PointerVariableAccess).getTarget() =
      innerPointer
  )
}

/**
 * Checks if any of the inner pointer patterns exist for the given variables.
 */
predicate hasInnerPointerTakenPattern(ValueVariable v, PointerVariable innerPointer) {
  hasInnerPointerAssignment(v, innerPointer)
  or
  hasInnerPointerDeclaration(v, innerPointer)
  or
  hasInnerPointerFunctionCall(v, innerPointer)
}

/**
 * Checks if a pointer variable is used after a GC trigger call.
 * The usage can be either a direct successor or a successor of the enclosing block.
 */
predicate isPointerUsedAfterGcTrigger(PointerVariableAccess pointerUsageAccess, GcTriggerCall gcTriggerCall) {
  pointerUsageAccess = gcTriggerCall.getASuccessor*()
  or
  pointerUsageAccess = gcTriggerCall.getEnclosingBlock().getASuccessor*()
}

predicate passedToGcTrigger(ValueVariable v, ValueAccess initVAccess, FunctionCall gcTriggerCall) {
  exists(int i |
    initVAccess = v.getAnAccess() and
    i < count(gcTriggerCall.getAnArgument()) and
    gcTriggerCall.getAnArgumentSubExpr(i) = v.getAnAccess() and
    isArgumentNotSafe(gcTriggerCall.getTarget(), i)
  )
}

predicate accessedAfterGcTrigger(ValueVariable v, GcTriggerCall gcTriggerCall) {
  not exists(VariableAccess va |
    va.getTarget() = v and va = gcTriggerCall.getASuccessor*() and not isGuardAccess(va)
  )
}
