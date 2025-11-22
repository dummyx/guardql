#include "ruby_stubs.h"

/* Guard present, but no GC trigger occurs; should be redundant */
VALUE redundant_inline_guard(VALUE str) {
    const char *ptr = RSTRING_PTR(str); /* inner pointer, but no GC trigger */
    VALUE copy = rb_str_concat(str, str); /* uses existing VALUE, but no alloc here */
    (void)ptr;
    RB_GC_GUARD(str); /* redundant because no GC-triggering call between */
    return copy;
}
