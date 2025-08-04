/**
 * @name Unguarded VALUE Variables
 * @description Finds all VALUE variables that do not have garbage collection guards.
 *              This is an informational query to identify all unguarded VALUE variables,
 *              regardless of whether they need guards.
 * @kind problem
 * @id cpp/ruby/unguarded-value
 * @tags maintainability
 *       ruby
 *       garbage-collection
 * @severity info
 * @precision high
 */

import cpp
import lib.guard_checker

from ValueVariable v
where
  not hasGuard(v)
select v, "VALUE variable '" + v.getName() + "' is unguarded (no garbage collection guard)."