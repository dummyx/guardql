import cpp
import lib.guard_checker
import lib.types

from
  ValueVariable v, GcTriggerCall gtc, InnerPointerUsage pointerUsageAccess,
  InnerPointerTakingFunctionByNameCall innerPointerTaking
where needsGuard(v, gtc, pointerUsageAccess, innerPointerTaking) and hasGuard(v)
select v
