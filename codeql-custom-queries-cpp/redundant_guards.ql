import cpp
import lib.guard_checker

from ValueVariable v
where
  not exists(
    PointerVariable p, GcTriggerCall gtc, PointerVariableAccess pointerUsageAccess,
    PointerDerivationAction derivationSite
  |
    needsGuard(v, p, gtc, pointerUsageAccess, derivationSite)
  ) and
  hasGuard(v)
select v
