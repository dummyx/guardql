import cpp
import lib.guard_checker
import lib.patterns
import lib.types

from
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingExpr innerPointerTaking
where needsGuard(v, gtc, pointerUsageAccess, innerPointerTaking) and not hasGuard(v)
select v, v.getInitializer(), innerPointerTaking, gtc, pointerUsageAccess
