import cpp
import lib.guard_checker

from ValueVariable v
where
  not exists(
    PointerVariable p, GcTriggerCall gtc, PointerVariableAccess pointerUsageAccess,
    PointerDerivationAction innerPointerTaking
  |
    needsGuard(v, p, gtc, pointerUsageAccess, innerPointerTaking)
  ) and
  hasGuard(v)
select v
