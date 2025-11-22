#include "ruby_stubs.h"

struct foo { int x; };

/* DATA_PTR-derived pointer used after GC trigger; guard the VALUE */
VALUE data_ptr_guard_example(VALUE obj) {
    struct foo *p = (struct foo *)DATA_PTR(obj); /* inner pointer */
    VALUE res = rb_str_new("foo", 3);            /* GC trigger */
    p->x = 7;                                    /* pointer reused */
    RB_GC_GUARD(obj);                            /* guard after use */
    return res;
}
