#include "ruby_stubs.h"

/* Mirrors weakmap.c wmap_inspect_i: pointer extraction + GC trigger + guard */
VALUE wmap_inspect_like(VALUE str) {
    const char *ptr = RSTRING_PTR(str);        /* inner pointer */
    VALUE res = rb_str_new(ptr, 5);            /* GC trigger */
    rb_str_concat(res, str);                   /* uses ptr-backed string */
    RB_GC_GUARD(str);                          /* guard after last ptr use */
    return res;
}
