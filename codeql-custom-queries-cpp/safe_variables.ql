/**
 * @name Safe VALUE Variables
 * @description Finds VALUE variables that do not need garbage collection guards.
 *              These variables are safe from garbage collection issues based on
 *              their usage patterns.
 * @kind problem
 * @id cpp/ruby/safe-value
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
  not needsGuard(v)
select v, "VALUE variable '" + v.getName() + "' is safe and does not need a garbage collection guard."