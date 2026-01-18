#include "ruby_stubs.h"

/* Safe: VALUE comes from rb_scan_args (argv-backed) */
VALUE scan_args_safe(int argc, const VALUE *argv) {
    VALUE str;
    rb_scan_args(argc, argv, "01", &str);
    const char *ptr = RSTRING_PTR(str);
    rb_str_new("x", 1); /* GC trigger */
    return INT2NUM(ptr[0]);
}
