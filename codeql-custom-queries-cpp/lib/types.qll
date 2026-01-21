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

class InnerPointerTakingMacroInvocation extends MacroInvocation {
  InnerPointerTakingMacroInvocation() {
    this.getMacroName() in [
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
        "rb_ruby_debug_ptr",
        "TypedData_Make_Struct",
        "TypedData_Wrap_Struct",
        "Data_Make_Struct",
        "Data_Wrap_Struct"
      ]
  }
}

class InnerPointerTakingExpr extends Expr {
  InnerPointerTakingExpr() {
    this instanceof InnerPointerTakingFunctionByNameCall
    or
    exists(InnerPointerTakingMacroInvocation mi | this = mi.getExpr())
    or
    (
      this instanceof FunctionCall and
      this.(FunctionCall).getTarget() instanceof InnerPointerGetterFunction
    )
  }
}

class InnerPointerGetterFunction extends Function {
  InnerPointerGetterFunction() {
    this.getType() instanceof PointerType and
    exists(ValueVariable param |
      param instanceof Parameter and
      param.getParentScope() = this and
      (
        exists(InnerPointerTakingMacroInvocation mi |
          mi.getEnclosingFunction() = this and
          mi.getUnexpandedArgument(0).regexpMatch(".*\\b" + param.getName() + "\\b.*")
        )
        or
        exists(InnerPointerTakingFunctionByNameCall fc |
          fc.getEnclosingFunction() = this and
          fc.getAnArgument().(ValueAccess).getTarget() = param
        )
      )
    )
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
        "rb_ruby_debug_ptr",
        "rb_data_typed_object_make",
        "rb_data_typed_object_zalloc",
        "rb_data_typed_object_wrap",
        "rb_data_object_make",
        "rb_data_object_zalloc",
        "rb_data_object_wrap",
        "TypedData_Make_Struct",
        "TypedData_Wrap_Struct",
        "Data_Make_Struct",
        "Data_Wrap_Struct"
      ]
  }
}

class InnerPointerUsage extends ControlFlowNode {
  InnerPointerUsage() {
    this instanceof PointerVariableAccess or
    this instanceof InnerPointerTakingExpr
  }
}

class ValueAccess extends VariableAccess {
  ValueAccess() { this.getTarget() instanceof ValueVariable }
}

class PointerVariable extends Variable {
  PointerVariable() { this.getType() instanceof PointerType }
}

class PointerVariableAccess extends VariableAccess {
  PointerVariableAccess() { this.getTarget() instanceof PointerVariable }
}

class GuardedPtr extends Variable {
  GuardedPtr() {
    this.getType().getName() = "volatile VALUE *" and
    this.getName() = "rb_gc_guarded_ptr"
  }
}
