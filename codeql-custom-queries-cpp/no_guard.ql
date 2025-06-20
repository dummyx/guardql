import cpp
import guard_checker

from ValueVariable v 
where
  not hasGuard(v)
select v