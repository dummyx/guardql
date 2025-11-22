#include "ruby_stubs.h"

/* Missing guard: inner pointer used across GC trigger without RB_GC_GUARD */
VALUE missing_guard_example(VALUE str) {
    const char *ptr = RSTRING_PTR(str);        /* inner pointer */
    VALUE res = rb_str_new(ptr, 3);            /* GC trigger */
    rb_str_concat(res, str);                   /* uses ptr, but no guard */
    return res;                                /* should be flagged by missing_guards.ql */
}
