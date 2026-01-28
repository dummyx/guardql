# PoCs

This directory contains Ruby scripts used to reproduce and validate potential
missing-guard issues found by the CodeQL queries.

## Recommended entrypoints

- `tools/poc/poc_true_missings_runner.rb`: Runs **confirmed true-missing** PoCs in
  forked subprocesses (so a segfault doesn't stop the whole suite).
  - Example: `POC_DURATION=20 /path/to/ruby tools/poc/poc_true_missings_runner.rb`
- `tools/poc/poc_io_buffer_set_string.rb`: Direct reproducer for the confirmed
  `IO::Buffer#set_string` issue. It prints `iterations=...` and will segfault on
  vulnerable Rubies.
  - Example: `/path/to/ruby tools/poc/poc_io_buffer_set_string.rb`
- `tools/poc/poc_missing_all.rb`: Aggregate runner for multiple *candidate* cases.
  - Example: `POC_CASE_SECONDS=10 /path/to/ruby tools/poc/poc_missing_all.rb`

## Notes

- Some scripts use `tools/poc/poc_utils.rb` to add load paths for the local
  uninstalled `ruby/build-o3` build.
- If you don't see `[BUG]` output on a crash, check whether crash reports are
  being redirected via `RUBY_CRASH_REPORT` (or `--crash-report`).
- `tools/poc/adhoc/` contains older one-off scripts moved from the repo root.

