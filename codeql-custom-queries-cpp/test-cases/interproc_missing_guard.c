#include "ruby_stubs.h"

/* Interprocedural missing-guard case:
 * Caller extracts inner pointer and passes it to callee;
 * callee triggers GC and uses the pointer afterward.
 */

static VALUE callee_uses_pointer(const char *ptr, VALUE original) {
    VALUE tmp = rb_str_new(ptr, 4);   /* GC trigger */
    return rb_str_concat(tmp, original); /* uses ptr after potential GC */
}

VALUE interproc_missing_guard(VALUE str) {
    const char *ptr = RSTRING_PTR(str); /* inner pointer */
    VALUE res = callee_uses_pointer(ptr, str);
    return res; /* No RB_GC_GUARD(str); should be flagged as missing */
}
