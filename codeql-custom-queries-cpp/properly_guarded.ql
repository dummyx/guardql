import cpp
import guard_checker

from ValueVariable v
where
  isNeedGuard(v) and hasGuard(v)
select v