#include "ruby_stubs.h"

/* Mirrors prism/extension.c local loop: inner pointer from rb_id2name guarded */
VALUE prism_options_like(VALUE scope) {
    long count = RARRAY_LEN(scope);
    for (long i = 0; i < count; i++) {
        VALUE local = rb_ary_entry(scope, i);
        if (!RB_TYPE_P(local, T_SYMBOL)) continue;
        const char *name = rb_id2name(local);  /* inner pointer from VALUE */
        (void)name;
        RB_GC_GUARD(local);                    /* guard after pointer use */
    }
    return scope;
}
