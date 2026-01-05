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
 * Checks if there's a declaration of a PointerVariable initialized with an InnerPointerTakingFunctionByNameCall
 * that takes the given ValueVariable as an argument.
 *
 * ```
 * VALUE a;
 * ptr* b = inner_pointer_taking_function(a);
 * ```
 */
predicate hasInnerPointerDeclaration(
  ValueVariable v, PointerVariable innerPointer,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
) {
  exists(Declaration decl, VariableDeclarationEntry declEntry |
    decl.getADeclarationEntry() = declEntry and
    declEntry.getVariable() = innerPointer and
    innerPointer.getInitializer().getExpr() = innerPointerTaking and
    innerPointerTaking.getAnArgument().getAChild*().(ValueAccess).getTarget() = v and
    innerPointerTaking = innerPointerTaking
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
  // or
  // hasInnerPointerDeclaration(v, innerPointer, innerPointerTaking)
  hasInnerPointerFunctionCall(v, innerPointer, innerPointerTaking)
}

/**
 * Checks if a pointer variable is used after a GC trigger call.
 * The usage can be either a direct successor or a successor of the enclosing block.
 */
predicate isPointerUsedAfterGcTrigger(
  PointerVariableAccess pointerUsageAccess, GcTriggerCall gcTriggerCall
) {
  // not notAfter(gcTriggerCall, pointerUsageAccess)
  gcTriggerCall.getASuccessor+() = pointerUsageAccess
}

/**
 * Interprocedural: pointer argument is passed to a callee that performs an
 * allocation/GC-triggering call using that parameter.
 */
predicate pointerPassedToGcAlloc(FunctionCall call, PointerVariableAccess pAccess) {
  exists(int i |
    call.getAnArgumentSubExpr(i) = pAccess and
    calleeParameterUsedInAlloc(call.getTarget(), i)
  )
}

predicate calleeParameterUsedInAlloc(Function callee, int idx) {
  exists(FunctionCall innerCall, VariableAccess paramUse |
    innerCall.getEnclosingFunction() = callee and
    isAllocOrGcCall(innerCall) and
    (
      innerCall.getAnArgument() = paramUse and
      paramUse.getTarget() = callee.getParameter(idx)
      or
      innerCall.getAnArgument().getAChild*() = callee.getParameter(idx).getAnAccess()
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

predicate notAccessedAfterGcTrigger(ValueVariable v, GcTriggerCall gcTriggerCall) {
  not exists(VariableAccess va |
    va.getTarget() = v and va = gcTriggerCall.getASuccessor+() and not isGuardAccess(va)
  )
  // notAfter(gcTriggerCall, v.getAnAccess())
}

predicate notAfter(ControlFlowNode a, ControlFlowNode b) {
  not a.getBasicBlock().getASuccessor+() = b.getBasicBlock()
}

predicate after(ControlFlowNode a, ControlFlowNode b) {
  a.getBasicBlock().getASuccessor+() = b.getBasicBlock()
}

/**
 * Detects direct inline pointer usage pattern: func(RSTRING_PTR(str))
 * where str is used directly without being stored in an intermediate pointer variable
 */
predicate directInlinePointerUsage(ValueVariable v, FunctionCall gcTrigger, FunctionCall laterCall) {
  exists(FunctionCall ptrExtract |
    // Inner pointer extraction directly used as argument
    ptrExtract.getTarget().getName() in [
        "RSTRING_PTR", "RARRAY_PTR", "RARRAY_CONST_PTR", "RHASH_TBL", "RSTRUCT_PTR", "DATA_PTR",
        "RREGEXP_PTR", "rb_string_value_ptr", "rb_string_value_cstr", "StringValueCStr",
        "rb_str_ptr_readonly", "RBIGNUM_DIGITS"
      ] and
    ptrExtract.getAnArgument().(VariableAccess).getTarget() = v and
    // GC trigger occurs
    ptrExtract.getASuccessor+() = gcTrigger and
    gcTrigger.getTarget().getName() in [
        "rb_str_new", "rb_str_buf_new", "rb_str_resize", "rb_str_concat", "rb_str_append",
        "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store", "rb_hash_new", "rb_hash_aset",
        "rb_hash_lookup2", "rb_obj_alloc", "rb_class_new_instance", "rb_funcall", "ALLOC",
        "ALLOC_N", "REALLOC_N"
      ] and
    // Later call uses the same pointer extraction pattern
    gcTrigger.getASuccessor+() = laterCall and
    exists(FunctionCall laterPtrExtract |
      laterCall.getAnArgument() = laterPtrExtract and
      laterPtrExtract.getTarget().getName() = ptrExtract.getTarget().getName() and
      laterPtrExtract.getAnArgument().(VariableAccess).getTarget() = v
    ) and
    // All in same function
    exists(Function f |
      ptrExtract.getEnclosingFunction() = f and
      gcTrigger.getEnclosingFunction() = f and
      laterCall.getEnclosingFunction() = f
    )
  )
}
