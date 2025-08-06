/**
 * @name Missing Guard for VALUE Variables
 * @description Finds VALUE variables that need garbage collection guards but are missing them.
 *              This can lead to use-after-free vulnerabilities if garbage collection occurs
 *              while inner pointers are still being used.
 * @kind problem
 * @id cpp/ruby/missing-gc-guard
 * @tags security
 *       correctness
 *       ruby
 *       garbage-collection
 * @severity error
 * @precision high
 */

import cpp
import lib.guard_checker
import lib.patterns
import lib.types

/**
 * Common GC-triggering functions in CRuby (balanced precision)
 */
predicate isCommonGcTrigger(Function f) {
  f.getName() in [
    // String operations
    "rb_str_new", "rb_str_buf_new", "rb_str_tmp_new", "rb_str_resize", 
    "rb_str_concat", "rb_str_append", "rb_str_dup",
    // Array operations  
    "rb_ary_new", "rb_ary_push", "rb_ary_concat", "rb_ary_store",
    // Hash operations
    "rb_hash_new", "rb_hash_aset", "rb_hash_lookup2",
    // Object creation
    "rb_obj_alloc", "rb_class_new_instance", "rb_funcall",
    // Direct GC
    "rb_gc_start", "rb_gc", "rb_objspace_garbage_collect",
    // Memory allocation
    "ALLOC", "ALLOC_N", "REALLOC_N"
  ]
}

/**
 * Improved precision pattern for guard detection
 */
predicate improvedNeedsGuard(ValueVariable v) {
  exists(
    FunctionCall ptrExtract,
    FunctionCall gcTrigger,
    VariableAccess ptrUse,
    Assignment ptrAssign,
    PointerVariable innerPtr
  |
    // 1. Inner pointer extracted: ptr = RSTRING_PTR(value) or similar
    ptrExtract.getTarget().getName() in ["RSTRING_PTR", "RARRAY_PTR", "RARRAY_CONST_PTR"] and
    ptrExtract.getAnArgument().(VariableAccess).getTarget() = v and
    
    // 2. Assigned to a pointer variable
    ptrAssign.getRValue() = ptrExtract and
    ptrAssign.getLValue().(VariableAccess).getTarget() = innerPtr and
    
    // 3. GC trigger after extraction
    ptrExtract.getASuccessor+() = gcTrigger and
    isCommonGcTrigger(gcTrigger.getTarget()) and
    
    // 4. Pointer used after GC trigger
    ptrUse.getTarget() = innerPtr and
    gcTrigger.getASuccessor+() = ptrUse and
    
    // 5. Meaningful usage of pointer
    exists(Expr parent | parent = ptrUse.getParent() |
      parent instanceof ArrayExpr or
      parent instanceof PointerDereferenceExpr or
      parent instanceof FunctionCall or
      parent instanceof Assignment
    ) and
    
    // 6. All within same function
    exists(Function f |
      ptrExtract.getEnclosingFunction() = f and
      gcTrigger.getEnclosingFunction() = f and
      ptrUse.getEnclosingFunction() = f
    ) and
    
    // 7. Reasonable proximity (within about 20 control flow steps)
    exists(ControlFlowNode start, ControlFlowNode end |
      start = ptrExtract and end = ptrUse and
      start.getASuccessor().getASuccessor().getASuccessor().getASuccessor().getASuccessor().
      getASuccessor().getASuccessor().getASuccessor().getASuccessor().getASuccessor().
      getASuccessor().getASuccessor().getASuccessor().getASuccessor().getASuccessor().
      getASuccessor().getASuccessor().getASuccessor().getASuccessor().getASuccessor*() = end
    )
  )
}

from ValueVariable v
where
  improvedNeedsGuard(v) and not hasGuard(v) and
  // Filter out very short variable names (often temporaries)
  v.getName().length() > 2
select v, "VALUE variable '" + v.getName() + "' needs a garbage collection guard but is missing one."