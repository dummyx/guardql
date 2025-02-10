import cpp
import guard_checker

from ValueVariable v
where
  hasGuard(v) and not isNeedGuard(v)
select v