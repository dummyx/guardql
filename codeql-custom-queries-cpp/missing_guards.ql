import cpp
import lib.guard_checker
import lib.patterns
import lib.types

from ValueVariable v
where
  isGuardCandidate(v) and
  needsGuard(v) and
  not hasGuard(v)
select
  v
