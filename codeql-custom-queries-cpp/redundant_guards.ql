import cpp
import lib.guard_checker

from ValueVariable v
where
  not exists(PointerVariable p | needsGuard(v, p)) and
  hasGuard(v)
select v, v.getName(), v.getFile().getAbsolutePath(), v.getDefinitionLocation(), getGuardInsertionLine(v)
