/**
 * @name Redundantly Guarded VALUE Variables
 * @description Finds VALUE variables that have garbage collection guards but do not need them.
 *              These guards are unnecessary and could be removed to simplify the code,
 *              though they do not cause correctness issues.
 * @kind problem
 * @id cpp/ruby/redundant-gc-guard
 * @tags maintainability
 *       ruby
 *       garbage-collection
 * @severity recommendation
 * @precision high
 */

import cpp
import lib.guard_checker

from ValueVariable v
where
  hasGuard(v) and not isNeedGuard(v)
select v, "VALUE variable '" + v.getName() + "' has a redundant garbage collection guard."