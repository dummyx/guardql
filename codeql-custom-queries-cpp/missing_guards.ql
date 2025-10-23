import cpp
import lib.guard_checker
import lib.patterns
import lib.types

from ValueVariable v, PointerVariable p, GcTriggerCall gtc,
     PointerVariableAccess pointerUsageAccess, ControlFlowNode innerPointerTaking
where
  needsGuard(v, p, gtc, pointerUsageAccess, innerPointerTaking) and not hasGuard(v)
select v, p, gtc, pointerUsageAccess, innerPointerTaking
