import cpp
import lib.guard_checker
import lib.types

from ValueVariable v, PointerVariable p, GcTriggerCall gtc,
     PointerVariableAccess pointerUsageAccess, PointerDerivationAction derivationSite
where
  needsGuard(v, p, gtc, pointerUsageAccess, derivationSite) and hasGuard(v)
select v
