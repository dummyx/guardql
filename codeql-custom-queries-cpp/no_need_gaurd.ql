/**
 * @name VALUE Variables That Do Not Need Guards
 * @description Finds VALUE variables that do not need garbage collection guards.
 *              These variables are safe from garbage collection issues based on
 *              their usage patterns.
 * @kind problem
 * @id cpp/ruby/no-need-gc-guard
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
  not isNeedGuard(v)
select v, "VALUE variable '" + v.getName() + "' does not need a garbage collection guard."