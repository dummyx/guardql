#include "ruby_stubs.h"

/* Missing guard: VALUE reassigned to a new object before pointer derivation */
VALUE scan_args_reassigned_missing_guard(int argc, const VALUE *argv) {
    VALUE str;
    rb_scan_args(argc, argv, "01", &str);
    str = rb_str_new("y", 1);        /* new VALUE (not argv-backed) */
    const char *ptr = RSTRING_PTR(str);
    rb_str_new("x", 1);              /* GC trigger */
    return INT2NUM(ptr[0]);          /* pointer reused */
}
