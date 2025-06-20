import cpp
import guard_checker

from ValueVariable v 
where
  not isNeedGuard(v)
select v