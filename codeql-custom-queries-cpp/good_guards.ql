import cpp
import lib.guard_checker
import lib.types

from ValueVariable v
where
  exists(PointerVariable p | needsGuard(v, p)) and
  hasGuard(v)
select v