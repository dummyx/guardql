import cpp
import lib.guard_checker

from ValueVariable v
where
  not exists(
    GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
    InnerPointerTakingFunctionByNameCall innerPointerTaking
  |
    needsGuard(v, gtc, pointerUsageAccess, innerPointerTaking)
  ) and
  hasGuard(v)
select v
