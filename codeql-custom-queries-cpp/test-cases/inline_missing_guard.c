#include "ruby_stubs.h"

/* Inline pointer extraction reused without guard */
VALUE inline_missing_guard(VALUE str) {
    VALUE part = rb_str_new(RSTRING_PTR(str), 3);  /* GC trigger with inline ptr */
    VALUE later = rb_str_new(RSTRING_PTR(str), 2); /* reuse inline ptr pattern */
    return rb_str_concat(part, later);             /* no RB_GC_GUARD(str) */
}
