import cpp
import lib.guard_checker
import lib.types

from ValueVariable v, PointerVariable p, GcTriggerCall gtc,
     PointerVariableAccess pointerUsageAccess, PointerDerivationAction innerPointerTaking
where
  needsGuard(v, p, gtc, pointerUsageAccess, innerPointerTaking) and hasGuard(v)
select v
