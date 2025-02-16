import cpp
import guard_checker

from ValueVariable v
where
  isNeedGuard(v) and (not hasGuard(v))
select v