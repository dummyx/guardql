import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

import guard_checker

// gc_enter
// 

from 
    Stmt s, Function func, Stmt sub
where
    s = func.getBlock() and sub = s.getAChild*() and func.getName() = "rb_imemo_new"

select s, sub, sub.getAQlClass()