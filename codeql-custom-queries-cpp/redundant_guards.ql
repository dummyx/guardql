import cpp
import lib.guard_checker

from ValueVariable v
where
  isGuardCandidate(v) and
  hasGuard(v) and
  not needsGuard(v)
select v
