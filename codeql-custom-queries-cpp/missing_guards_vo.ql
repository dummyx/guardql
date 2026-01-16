import cpp
import lib.guard_checker

from ValueVariable v
where
  exists(
    PointerVariable p, GcTriggerCall gtc, PointerVariableAccess pointerUsageAccess,
    PointerDerivationAction derivationSite
  |
    needsGuard(v, p, gtc, pointerUsageAccess, derivationSite)
  ) and
  not hasGuard(v)
select v
