/**
 * @name All RB_GC_GUARD Usage
 * @description Finds all VALUE variables that have RB_GC_GUARD calls.
 *              Shows comprehensive guard usage in the codebase.
 * @kind problem
 * @id cpp/ruby/all-rb-gc-guard-usage
 * @tags maintainability
 *       ruby
 *       garbage-collection
 * @severity info
 * @precision high
 */

import cpp
import lib.guard_checker
import lib.types

from ValueVariable v
where
  hasGuard(v)
select v, "VALUE variable '" + v.getName() + "' is protected by RB_GC_GUARD."