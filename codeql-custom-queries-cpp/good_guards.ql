import cpp
import lib.guard_checker
import lib.types

from
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingExpr innerPointerTaking
where needsGuard(v, gtc, pointerUsageAccess, innerPointerTaking) and hasGuard(v)
select v, innerPointerTaking, gtc, pointerUsageAccess
