import cpp
import lib.guard_checker

from ValueVariable v
where
  isGuardCandidate(v) and
  hasGuard(v) and
  not needsGuard(v) and
  not guardLikelyNeeded(v)
select v
