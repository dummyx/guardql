import cpp
import lib.guard_checker
import lib.patterns
import lib.types

from ValueVariable v, PointerVariable p, GcTriggerCall gtc,
     PointerVariableAccess pointerUsageAccess, PointerDerivationAction derivationSite
where
  needsGuard(v, p, gtc, pointerUsageAccess, derivationSite) and not hasGuard(v)
select v, derivationSite, gtc, pointerUsageAccess
