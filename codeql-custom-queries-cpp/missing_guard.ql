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

from ValueVariable v
where
  isNeedGuard(v) and (not hasGuard(v))
select v, "VALUE variable '" + v.getName() + "' needs a garbage collection guard but is missing one."