# PoCs

This directory contains Ruby scripts used to reproduce and validate potential
missing-guard issues found by the CodeQL queries.

## Recommended entrypoints

- `tools/poc/poc_true_missings_runner.rb`: Runs **confirmed true-missing** PoCs in
  forked subprocesses (so a segfault doesn't stop the whole suite).
  - Example: `POC_DURATION=20 /path/to/ruby tools/poc/poc_true_missings_runner.rb`
- `tools/poc/poc_io_buffer_set_string.rb`: Direct reproducer for the confirmed
  `IO::Buffer#set_string` issue. It prints `iterations=...` and will segfault on
  Rubies with the GC lifetime bug.
  - Example: `/path/to/ruby tools/poc/poc_io_buffer_set_string.rb`
- `tools/poc/poc_arith_seq_inspect.rb`: Direct reproducer for the confirmed
  `ArithmeticSequence#inspect` issue (crashes under high GC compaction pressure).
  - Example: `POC_SECONDS=60 /path/to/ruby tools/poc/poc_arith_seq_inspect.rb`
- `tools/poc/poc_str_transcode0_compactfree.rb`: Direct reproducer for the
  confirmed `String#encode`/`str_transcode0` issue. It rotates through
  source-backed newline/XML decorator variants and raises on output corruption.
  - Example: `POC_ADD_BUILD_LOAD_PATH=1 POC_AUTO_COMPACT=1 POC_SECONDS=60 /path/to/ruby tools/poc/poc_str_transcode0_compactfree.rb`
- `tools/poc/poc_missing_all.rb`: Aggregate runner for multiple *candidate* cases.
  - Example: `POC_CASE_SECONDS=10 /path/to/ruby tools/poc/poc_missing_all.rb`
- `tools/poc/poc_missing_candidates_runner.rb`: Runs the current *missing-guard candidate* case set
  in forked subprocesses (good for quickly spotting crashes without stopping at the first one).
  - Example: `POC_DURATION=15 /path/to/ruby tools/poc/poc_missing_candidates_runner.rb`
- `tools/poc/current_missing_registry.rb`: Builds a site-level registry from the
  detailed missing-query CSV and maps each current site to a confirmed or
  candidate PoC.
  - Example: `ruby tools/poc/current_missing_registry.rb --detail /tmp/guardql_ruby_missing_detail_after.csv`
- `tools/poc/poc_extreme_campaign.rb`: Runs every registry-mapped PoC across
  repeated GC compaction profiles and writes a result CSV.
  - Example: `ruby tools/poc/poc_extreme_campaign.rb --ruby /path/to/ruby --registry tools/poc/current_missing_registry.csv --output /tmp/guardql_current_missing_extreme.csv`
  - Quick check: `ruby tools/poc/poc_extreme_campaign.rb --ruby /path/to/ruby --quick --exclude-confirmed`
- `tools/poc/poc_parallel_campaign.py`: Runs the same campaign target-by-target with worker-level parallelism, writes per-target logs next to the output, and merges the CSV rows.
  - Example: `python3 tools/poc/poc_parallel_campaign.py --registry tools/poc/current_missing_registry.csv --output /tmp/guardql_current_missing_extreme.csv --ruby /path/to/ruby --turns 3 --duration 30 --workers 8`

## Notes

- `tools/poc/poc_utils.rb` can optionally add load paths for the local
  uninstalled `ruby/build-o3` build. Enable via `POC_ADD_BUILD_LOAD_PATH=1`.
- If you don't see `[BUG]` output on a crash, check whether crash reports are
  being redirected via `RUBY_CRASH_REPORT` (or `--crash-report`).
- Treat compaction as part of the GC bug model. A missing guard can matter even
  when the owner object is still referenced somewhere, because the object may not
  be visible to GC as a live stack root and compaction can move it, invalidating a
  raw pointer derived before the move.
- Short negative runs are only bounded negative evidence. Some compaction-driven
  cases need more process turns, longer durations, more iterations, and explicit
  `GC.compact` or `GC.auto_compact` pressure before they fail consistently.
- `tools/poc/adhoc/` contains older one-off scripts moved from the repo root.
