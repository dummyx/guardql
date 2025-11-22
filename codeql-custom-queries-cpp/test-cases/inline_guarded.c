#include "ruby_stubs.h"

/* Inline pointer extraction reused with guard present */
VALUE inline_guarded(VALUE str) {
    VALUE part = rb_str_new(RSTRING_PTR(str), 3);  /* GC trigger with inline ptr */
    VALUE later = rb_str_new(RSTRING_PTR(str), 2); /* reuse inline ptr pattern */
    VALUE out = rb_str_concat(part, later);
    RB_GC_GUARD(str);                              /* guard original VALUE */
    return out;
}
