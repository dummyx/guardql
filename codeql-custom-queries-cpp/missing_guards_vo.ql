import cpp
import lib.guard_checker

from ValueVariable v
where
  exists(
    GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
    InnerPointerTakingExpr innerPointerTaking
  |
    needsGuard(v, gtc, pointerUsageAccess, innerPointerTaking)
  ) and
  not hasGuard(v)
select v
