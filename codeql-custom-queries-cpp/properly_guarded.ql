/**
 * @name Properly Guarded VALUE Variables
 * @description Finds VALUE variables that need garbage collection guards and have them.
 *              These variables are correctly protected against garbage collection issues.
 * @kind problem
 * @id cpp/ruby/correctly-guarded
 * @tags maintainability
 *       ruby
 *       garbage-collection
 * @severity info
 * @precision high
 */

import cpp
import lib.guard_checker
import lib.types

/**
 * Enhanced properly guarded detection
 */
predicate isProperlyGuarded(ValueVariable v) {
  // Pattern 1: Variables that have clear guard needs and guards
  comprehensiveNeedsGuard(v) and hasGuard(v)
  or
  // Pattern 2: String variables with RSTRING_PTR usage and guards
  exists(FunctionCall rStringPtr |
    rStringPtr.getTarget().hasName("RSTRING_PTR") and
    rStringPtr.getAnArgument().(VariableAccess).getTarget() = v and
    hasGuard(v)
  )
  or
  // Pattern 3: Variables in extensions that are guarded (extensions often need more guards)
  isInExtension(v) and hasGuard(v) and isStringVariable(v)
  or
  // Pattern 4: Variables used with inner pointer functions and guarded
  exists(FunctionCall innerCall |
    innerCall.getTarget().getName() in [
      "RSTRING_PTR", "RARRAY_PTR", "RARRAY_CONST_PTR", "RHASH_TBL"
    ] and
    innerCall.getAnArgument().(VariableAccess).getTarget() = v and
    hasGuard(v)
  )
  or
  // Pattern 5: Function parameters that are guarded
  exists(Parameter param |
    v = param and
    param.getType().getName() = "VALUE" and
    hasGuard(v) and
    // Parameter is used meaningfully in the function
    exists(VariableAccess use |
      use.getTarget() = v and
      (
        exists(FunctionCall call | call.getAnArgument() = use) or
        exists(Assignment assign | assign.getRValue().getAChild*() = use)
      )
    )
  )
}

from ValueVariable v
where
  isProperlyGuarded(v) and
  // Quality filters
  v.getName().length() > 1 and
  not v.getName().matches("tmp%") and
  // Ensure it's actually guarded
  hasGuard(v)
select v, "VALUE variable '" + v.getName() + "' is properly guarded against garbage collection."