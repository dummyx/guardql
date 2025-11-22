Quick C fixtures mirroring real RB_GC_GUARD patterns from CRuby (weakmap, prism, yjit) plus a missing-guard case and a redundant-guard case.

## Layout
- `ruby_stubs.h` – minimal VALUE/RB_GC_GUARD/GC-trigger/pointer-extractor shims to keep the fixtures self contained.
- `weakmap_like.c` – pointer extracted via `RSTRING_PTR`, GC trigger happens, guard placed after last pointer use (expected **good guard**).
- `prism_like.c` – loop over locals, inner pointer via `rb_id2name`, guarded (expected **good guard**).
- `yjit_like.c` – multiple VALUEs guarded after GC-triggering hash updates (expected **good guards**).
- `missing_guard.c` – pointer extracted then GC trigger but no guard (expected **missing_guard** finding).
- `redundant_guard.c` – guard without any pointer extraction/GC trigger (expected **redundant_guard** finding).
- `interproc_missing_guard.c` – derived pointer passed to another function that triggers GC and uses the pointer (expected **missing_guard** if interprocedural pointer use is modeled).
- `array_guard.c` – `RARRAY_PTR` inner pointer used after `rb_ary_push`, guarded (expected **good guard**).
- `data_ptr_guard.c` – `DATA_PTR` inner pointer used after `rb_str_new`, guarded (expected **good guard**).
- `inline_missing_guard.c` – inline `RSTRING_PTR` argument to `rb_str_new` reused later without guard (expected **missing_guard** via inline pattern).
- `inline_guarded.c` – inline pointer extraction with guard present (expected **good guard**).
- `redundant_inline_guard.c` – pointer extracted but no GC trigger; guard present (expected **redundant_guard**).
- `redundant_param_guard.c` – guard on parameter without pointer extraction or GC trigger (expected **redundant_guard**).

## Quick run with CodeQL
```bash
# From repo root
cd codeql-custom-queries-cpp/test-cases

# Build a small database (requires clang or cc)
codeql database create ../test-db --language=cpp --source-root . \
  --command="cc -c *.c"

# Run queries
codeql query run ../missing_guards.ql --database ../test-db --output ../missing_guards.bqrs
codeql bqrs decode --format=csv --output ../missing_guards.csv ../missing_guards.bqrs

codeql query run ../redundant_guards.ql --database ../test-db --output ../redundant_guards.bqrs
codeql bqrs decode --format=csv --output ../redundant_guards.csv ../redundant_guards.bqrs
```

You can swap in other queries (e.g., `good_guards.ql`, `all_guarded_variables.ql`) against the same database.
