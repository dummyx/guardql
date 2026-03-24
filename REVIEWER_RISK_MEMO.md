# Reviewer Risk Memo

## Likely Criticisms and Responses

1. "The missing-report validation is still too thin."
Response:
- The revision added three clean historical replay cases, each showing the same emitted site on the pre-fix revision and disappearance on the matching post-fix revision for the right reason.
- The paper now clearly distinguishes this replay evidence from selected current-snapshot case studies instead of mixing them together.

2. "The paper cherry-picks a few interesting current reports instead of validating the emitted set systematically."
Response:
- The main evaluation is now explicit about scope:
  - exhaustive redundant triage for all `9` potentially redundant reports
  - one fixed submission snapshot for all headline counts
  - selected current-snapshot case-study depth
  - separate historical replay validation for missing-report evidence
- This does not fully eliminate the concern, but it does stop the paper from implying broader validation than it actually has.

3. "This looks like a simple pattern matcher with limited novelty."
Response:
- The paper now states directly that the derive-trigger-use core becomes useful only with CRuby-specific modeling and disciplined triage.
- The lightweight ablation shows that removing just the one-step interprocedural disjunct drops missing reports from `75 / 74` to `67 / 66`, including useful sites such as `rb_str_format_m`, `rb_io_extract_modeenc`, and `rb_io_extract_encoding_option`.

4. "The dynamic evidence is weak because most current-snapshot stress reruns were negative."
Response:
- The paper no longer treats negative short stress results as validation.
- Instead, it reports them honestly as selected non-confirmatory reruns, while foregrounding the stronger evidence:
  - `2` local crash confirmations
  - `1` independent guard-adding fix
  - `3` historical replay cases

5. "The paper may overclaim on redundant guards or correctness."
Response:
- The revision keeps “potentially redundant” explicitly model-relative throughout.
- The paper reports the exhaustive triage of all `9` emitted potentially redundant guards as `4` likely redundant and `5` likely model false positives, and the conclusion is framed as utility plus bounded scope rather than broad correctness.

## Hardest Remaining Criticism

The hardest criticism remains the absence of a seeded random manual classification over a larger sample of current emitted missing reports. The historical replay evidence materially improves reviewer confidence, but a reviewer who specifically wants systematic current-snapshot precision evidence can still press on this point.
