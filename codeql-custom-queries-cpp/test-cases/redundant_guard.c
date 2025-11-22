#include "ruby_stubs.h"

/* Redundant guard: no inner pointer extraction or GC trigger */
VALUE redundant_guard_example(VALUE v) {
    VALUE copy = v;
    RB_GC_GUARD(copy); /* should be reported by redundant_guards.ql */
    return copy;
}
