import cpp
import lib.guard_checker

from ValueVariable v
where isGuardCandidate(v) and needsGuard(v) and not hasGuard(v)
select v
