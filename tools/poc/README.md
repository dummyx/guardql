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
- `tools/poc/poc_arith_seq_inspect.rb`: Direct reproducer for the confirmed
  `ArithmeticSequence#inspect` issue (crashes under high GC compaction pressure).
  - Example: `POC_SECONDS=60 /path/to/ruby tools/poc/poc_arith_seq_inspect.rb`
- `tools/poc/poc_missing_all.rb`: Aggregate runner for multiple *candidate* cases.
  - Example: `POC_CASE_SECONDS=10 /path/to/ruby tools/poc/poc_missing_all.rb`
- `tools/poc/poc_missing_candidates_runner.rb`: Runs the current *missing-guard candidate* case set
  in forked subprocesses (good for quickly spotting crashes without stopping at the first one).
  - Example: `POC_DURATION=15 /path/to/ruby tools/poc/poc_missing_candidates_runner.rb`

## Notes

- `tools/poc/poc_utils.rb` can optionally add load paths for the local
  uninstalled `ruby/build-o3` build. Enable via `POC_ADD_BUILD_LOAD_PATH=1`.
- If you don't see `[BUG]` output on a crash, check whether crash reports are
  being redirected via `RUBY_CRASH_REPORT` (or `--crash-report`).
- `tools/poc/adhoc/` contains older one-off scripts moved from the repo root.
