import cpp
import lib.guard_checker
import lib.patterns
import lib.types

from ValueVariable v
where
  isTarget(v)
select v, v.getName(), v.getFile().getRelativePath(), min(getGuardInsertionLineBR(v))
