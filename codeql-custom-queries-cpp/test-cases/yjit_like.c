#include "ruby_stubs.h"

/* Mirrors yjit.c rb_yjit_add_frame: multiple VALUEs guarded after GC triggers */
VALUE rb_yjit_add_frame_like(VALUE hash, VALUE frame) {
    VALUE frame_id = PTR2NUM(frame);
    if (rb_hash_aref(hash, frame_id)) {
        return hash;
    }

    VALUE frame_info = rb_hash_new();          /* GC trigger: allocation */
    VALUE name = rb_profile_frame_full_label(frame);
    VALUE file = rb_profile_frame_absolute_path(frame);
    VALUE line = rb_profile_frame_first_lineno(frame);
    rb_hash_aset(frame_info, name, file);      /* potential GC trigger */
    rb_hash_aset(frame_info, line, frame);     /* potential GC trigger */
    rb_hash_aset(hash, frame_id, frame_info);  /* potential GC trigger */

    RB_GC_GUARD(frame);
    RB_GC_GUARD(hash);
    RB_GC_GUARD(frame_id);
    RB_GC_GUARD(frame_info);
    return hash;
}
