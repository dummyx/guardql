import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.Macro
import semmle.code.cpp.exprs.Access
import semmle.code.cpp.controlflow.ControlFlowGraph

class ValueVariable extends Variable {
  ValueVariable() { this.getType().getName() = "VALUE" }
}

class InnerPointerTakingFunctionByNameCall extends FunctionCall {
  InnerPointerTakingFunctionByNameCall() {
    this.getTarget() instanceof InnerPointerTakingFunctionByName
  }
}

class InnerPointerTakingFunctionByName extends Function {
  InnerPointerTakingFunctionByName() {
    this.getName() in [
        "BDIGITS",
        "BIGNUM_DIGITS",
        "RSTRING_PTR",
        "RSTRING_END",
        "RSTRING_GETMEM",
        "RARRAY_PTR",
        "RARRAY_CONST_PTR",
        "RARRAY_PTR_USE",
        "rb_array_const_ptr",
        "rb_ary_ptr_use_start",
        "rb_ary_ptr_use_end",
        "DATA_PTR",
        "rb_data_object_get",
        "Data_Get_Struct",
        "RTYPEDDATA_DATA",
        "RTYPEDDATA_GET_DATA",
        "TypedData_Get_Struct",
        "rb_check_typeddata",
        "RREGEXP_PTR",
        "RREGEXP_SRC_PTR",
        "RSTRUCT_PTR",
        "rb_struct_ptr",
        "ROBJECT_IVPTR",
        "RFILE",
        "RB_IO_POINTER",
        "GetOpenFile",
        "RMATCH",
        "RMATCH_EXT",
        "RMATCH_REGS",
        "StringValuePtr",
        "StringValueCStr",
        "rb_string_value_ptr",
        "rb_string_value_cstr",
        "rb_gc_guarded_ptr",
        "rb_gc_guarded_ptr_val",
        "FilePathValue",
        "rb_fd_ptr",
        "rb_memory_view_get_item_pointer",
        "rb_ractor_local_storage_ptr",
        "rb_errno_ptr",
        "rb_ruby_verbose_ptr",
        "rb_ruby_debug_ptr"
      ]
  }
}

class PointerDerivationAction extends ControlFlowNode {
  PointerDerivationAction() {
    this instanceof Assignment or
    this instanceof InnerPointerTakingFunctionByNameCall
  }
}

class InnerPointerUsage extends ControlFlowNode {
  InnerPointerUsage() { this instanceof FunctionCall or this instanceof PointerVariableAccess }
}

class ValueVariableMatch extends Variable {
  ValueVariableMatch() { this.getType().getName().matches("%VALUE%") }
}

class ValueAccess extends VariableAccess {
  ValueAccess() { this.getTarget() instanceof ValueVariable }
}

class PointerVariable extends Variable {
  PointerVariable() {
    this.getType() instanceof PointerType or
    this.getType().getName().matches("%VALUE%")
  }
}

class FunctionPointerAccess extends VariableAccess {
  FunctionPointerAccess() { this.getTarget().getType() instanceof FunctionPointerType }
}

class PointerVariableAccess extends VariableAccess {
  PointerVariableAccess() { this.getTarget() instanceof PointerVariable }
}

class InnerPointerTakingFunctionByType extends Function {
  InnerPointerTakingFunctionByType() {
    this.getAParameter().getType().getName() = "VALUE" and
    (
      this.getType() instanceof PointerType or
      this.getAParameter().getType() instanceof PointerType
    )
  }
}

class InnerPointerTakingFunctionCallByType extends FunctionCall {
  InnerPointerTakingFunctionCallByType() {
    this.getTarget() instanceof InnerPointerTakingFunctionByType
  }
}

class GuardMacroInvocation extends MacroInvocation {
  GuardMacroInvocation() { this.getMacroName() = "RB_GC_GUARD" }
}

class InnerPointerTakingFunctionCall extends FunctionCall {
  InnerPointerTakingFunctionCall() {
    this.getAnArgument().getType().getName().matches("%VALUE %_") or
    this.getTarget().getType().getName().matches("%VALUE %")
  }
}

class GuardedPtr extends Variable {
  GuardedPtr() {
    this.getType().getName() = "volatile VALUE *" and
    this.getName() = "rb_gc_guarded_ptr"
  }
}

class ValuePtrVariable extends Variable {
  ValuePtrVariable() { this.getType().getName() = "VALUE *" }
}
