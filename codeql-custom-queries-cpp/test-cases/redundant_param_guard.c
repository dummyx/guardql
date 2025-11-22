#include "ruby_stubs.h"

/* Guard on parameter with no pointer extraction or GC trigger */
VALUE redundant_param_guard(VALUE obj) {
    VALUE copy = obj;
    RB_GC_GUARD(obj); /* expected redundant */
    return copy;
}
