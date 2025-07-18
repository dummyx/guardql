/**
 * @name Properly Guarded VALUE Variables
 * @description Finds VALUE variables that need garbage collection guards and have them.
 *              These variables are correctly protected against garbage collection issues.
 * @kind problem
 * @id cpp/ruby/properly-guarded
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
  isNeedGuard(v) and hasGuard(v)
select v, "VALUE variable '" + v.getName() + "' is properly guarded against garbage collection."