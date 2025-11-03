import cpp

import lib.guard_checker


from ValueAccess va , ControlFlowNode cfn 

where
  /*va.getFile().getBaseName().toString() = "array.c" and
  va.getEnclosingBlock() = b.getEnclosingElement() and
  not va.getEnclosingStmt*().getASuccessor*() = b*/

  va.getEnclosingFunction().getName() = "arith_seq_inspect" and
  va.getASuccessor+() = cfn and cfn instanceof PointerVariableAccess
select va, cfn