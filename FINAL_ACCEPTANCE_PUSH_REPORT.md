# Final Acceptance Push Report

## 1. What evidence was added

- Added three clean historical replay validation cases for emitted missing-guard reports:
  - `load.c:search_required` on `lookup_name`
  - `string.c:rb_str_buf_append` on `str2`
  - `compile.c:iseq_build_from_ary_body` on `labels_wrapper`
- Added one lightweight ablation that removes the one-step interprocedural disjunct from `needsGuard`.
- Reframed the evaluation around one submission snapshot, exhaustive redundant triage, historical replay validation, current-snapshot case studies, and the optional ablation.
- Hardened the reviewer-facing package:
  - rebuilt `submission/main.pdf`
  - rebuilt `submission/supplement.pdf`
  - removed stale `reference_comparison.csv`
  - created a clean neutral package at `xie-ismm-2026/anonymous_submission/`
  - sanitized the reviewer-facing replay CSV and supplement to omit exact CRuby revision identifiers
  - reran grep and PDF-text scans for `/home/`, `x17`, and raw 12+ hex strings

## 2. What experiments, queries, and PoCs were rerun

- Submission snapshot queries on `ruby-codeql-database`:
  - `codeql-custom-queries-cpp/missing_guards.ql`
  - `codeql-custom-queries-cpp/good_guards.ql`
  - `codeql-custom-queries-cpp/redundant_guards.ql`
- Historical replay reruns:
  - for each case, created pre-fix and post-fix CRuby worktrees
  - bootstrapped with `./autogen.sh` and `./configure --disable-install-doc`
  - built translation-unit CodeQL databases with `make <file>.o`
  - reran `codeql-custom-queries-cpp/missing_guards.ql`
- Ablation rerun:
  - `codeql-custom-queries-cpp/missing_guards_no_one_step_interproc_ablation.ql`
- Current-snapshot dynamic corroboration reruns:
  - local crash PoCs for `rb_str_format_m` and `io_buffer_set_string`
  - short compaction/compactfree stress reruns for the remaining selected current-snapshot cases
- Document builds:
  - rebuilt the paper and supplement through `nix shell nixpkgs#tectonic -c tectonic ...`

## 3. Final headline numbers used in the paper

- Submission snapshot on CRuby `v3_4_5`:
  - potential missing guards: `75` rows, `74` unique locations
  - existing guards matched by the model: `77` rows, `77` unique locations
  - potentially redundant guards: `9` rows, `9` unique locations
- Exhaustive potentially redundant triage:
  - `4` likely redundant
  - `5` likely model false positives
- Historical replay validation:
  - `3` clean replay cases
- Current-snapshot case-study evidence:
  - `2` local crashes
  - `1` independent corroborating fix
  - `8` selected emitted sites with no failure observed under short stress reruns
- Ablation:
  - removing one-step interprocedural reasoning drops missing reports from `75 / 74` to `67 / 66`

## 4. Historical replay outcome

Historical replay succeeded with `3` clean cases.

- `search_required` / `load.c`
  - parent revision: `391b6746cdc3fa39d1a5d832debe9c5b5dc39f51`
  - fix revision: `36966456c728b4faba8aa7c853cdccdfcf9a14ab`
  - pre-fix rerun reported `lookup_name`
  - post-fix rerun dropped `lookup_name` and retained nearby reports for `tmp` and `fname`
- `rb_str_buf_append` / `string.c`
  - parent revision: `d7f1ea71555c4d359de529b6058e4338ae247063`
  - fix revision: `2214bcb70d9f9120f1f3790ca340236c8f080991`
  - pre-fix rerun reported `str2`
  - post-fix rerun dropped `str2` while retaining unrelated `string.c` reports
- `iseq_build_from_ary_body` / `compile.c`
  - parent revision: `174b67169975160aa682d9b2c6ac5ccde2652105`
  - fix revision: `9d0a5148ae062a0481a4a18fbeb9cfd01dc10428`
  - pre-fix rerun reported `labels_wrapper`
  - post-fix rerun emitted no `compile.c` reports

The replay summary CSV is `xie-ismm-2026/repro/generated/historical_replay_validation.csv`. Reviewer-facing copies intentionally omit the raw revision identifiers.

## 5. Seeded manual classification status

- Seeded random classification of emitted missing reports was not done.
- Reason: Track A reached the stopping rule first with `3` convincing historical replay cases.
- Sample size: `0`
- Seed: `N/A`
- Category counts: `N/A`

## 6. Additional dynamic corroboration

- Obtained `2` local crash confirmations:
  - `string.c:rb_str_format_m`
  - `io_buffer.c:io_buffer_set_string`
- Obtained `1` independent corroborating emitted case:
  - `vm_backtrace.c:location_format`
- Retained `8` selected emitted sites with negative short stress results as explicitly non-confirmatory evidence.

## 7. Ablation status

- Added one ablation.
- Change:
  - removed the one-step interprocedural disjunct from `needsGuard`
- Result:
  - reports fell from `75 / 74` to `67 / 66`
  - eight unique emitted sites disappeared
  - lost sites included `rb_str_format_m`, `rb_io_extract_modeenc`, and `rb_io_extract_encoding_option`
- Interpretation used in the paper:
  - the one-step CRuby-specific summary materially contributes to practical checker coverage

## 8. Claims weakened or removed

- Removed the older reference-snapshot provenance story from the main narrative.
- Reframed the paper explicitly as a practitioner report / experience report, not a proof technique or security paper.
- Kept “potentially redundant” explicitly model-relative.
- Replaced the earlier missing-report validation story with a structured split between:
  - historical replay validation
  - selected current-snapshot case studies
- Avoided any claim that the current emitted missing reports were exhaustively validated.
- Sanitized reviewer-facing materials to avoid embedding exact CRuby revision identifiers where they were not needed to support the paper’s public claims.

## 9. Files changed

- Query and analysis artifacts:
  - `codeql-custom-queries-cpp/missing_guards_no_one_step_interproc_ablation.ql`
  - `xie-ismm-2026/repro/generated/ablation_no_one_step_interproc.csv`
  - `xie-ismm-2026/repro/generated/historical_replay_validation.csv`
  - `xie-ismm-2026/repro/historical-replay-20260324/README.md`
  - `xie-ismm-2026/repro/historical-replay-20260324/*`
- Paper sources:
  - `xie-ismm-2026/main.tex`
  - `xie-ismm-2026/01_introduction.tex`
  - `xie-ismm-2026/04_approach.tex`
  - `xie-ismm-2026/05_experiment.tex`
  - `xie-ismm-2026/06_discussion.tex`
  - `xie-ismm-2026/08_conclusion.tex`
  - `xie-ismm-2026/09_appendix.tex`
  - `xie-ismm-2026/references.bib`
- Reproducibility and submission docs:
  - `xie-ismm-2026/REPRODUCIBILITY.md`
  - `xie-ismm-2026/submission/README.md`
  - `xie-ismm-2026/submission/supplementary/REPRODUCIBILITY.md`
- Reviewer-facing outputs:
  - `xie-ismm-2026/submission/main.pdf`
  - `xie-ismm-2026/submission/supplement.pdf`
  - `xie-ismm-2026/submission/supplementary/generated/analysis_summary.csv`
  - `xie-ismm-2026/submission/supplementary/generated/redundant_classification.csv`
  - `xie-ismm-2026/submission/supplementary/generated/historical_replay_validation.csv`
  - `xie-ismm-2026/submission/supplementary/generated/missing_validation_sample.csv`
  - `xie-ismm-2026/submission/supplementary/generated/ablation_no_one_step_interproc.csv`
  - `xie-ismm-2026/submission/supplementary/generated/poc_summary.csv`
  - `xie-ismm-2026/anonymous_submission/*`

## 10. Final page count

- Main paper: `7` pages
- Supplement: `2` pages

The main paper stays well within the official ISMM 2026 CFP limit of `12` pages excluding bibliography, and the appendix material remains only in the separately submitted supplement.

## 11. Remaining top 5 reviewer risks

- Missing-report validation is stronger than before, but still rests on only three replayed historical fixes rather than a larger systematic sample.
- The current-snapshot evidence is still selected-case depth, not a seeded random classification of emitted missing reports.
- Only two current emitted cases were dynamically confirmed locally; the rest of the current-snapshot case-study evidence is weaker.
- The checker remains intentionally CRuby-specific, which helps usefulness but can invite criticism about generality.
- The redundant-report side is tractable and honest, but reviewers may still focus on the five remaining model false positives and ask for additional modeling of bignum and zlib patterns.
