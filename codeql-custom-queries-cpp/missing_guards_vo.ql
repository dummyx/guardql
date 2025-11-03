import cpp
import lib.guard_checker

from ValueVariable v
where
  exists(
    PointerVariable p, GcTriggerCall gtc, PointerVariableAccess pointerUsageAccess,
    PointerDerivationAction innerPointerTaking
  |
    needsGuard(v, p, gtc, pointerUsageAccess, innerPointerTaking)
  ) and
  not hasGuard(v)
select v
