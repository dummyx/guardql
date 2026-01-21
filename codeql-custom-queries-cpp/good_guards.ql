import cpp
import lib.guard_checker
import lib.types

from ValueVariable v
where isGuardCandidate(v) and needsGuard(v) and hasGuard(v)
select v
