#include "ruby_stubs.h"

/* Array inner pointer survives push; guard the VALUE holding it */
VALUE array_guard_example(VALUE ary) {
    VALUE *ptr = (VALUE *)RARRAY_PTR(ary); /* inner pointer */
    rb_ary_push(ary, LONG2NUM(42));        /* GC trigger */
    VALUE first = ptr[0];                  /* pointer reused */
    RB_GC_GUARD(ary);                      /* guard after pointer use */
    return first;
}
