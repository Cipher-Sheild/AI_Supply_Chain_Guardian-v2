# Final verification status — 18 October 2026

## Completed

- Real VS Code Copilot pair: safe proposal accepted and created; eval proposal reviewed and blocked before writing. Genuine saved scan JSON, audit PDFs, sanitized SDK tool transcript and matching adapter hash are retained.
- All ten existing upstream files read and labelled by Codex AI assistant, with concrete rationales and hashes: eight Accept, two Review. No human identity or personal attestation entered. This review made no new Guardian requests and is not formally blinded to historical system work.
- Previously skipped PostgreSQL restart/distributed-lock integration test passed on a separately created and migrated scratch database. The scratch database was removed; the operational database was not used for the test.
- Eighteen new inert fixtures and their AI labels/source/model hashes frozen before first scanning. All finalized with zero scan failures. Exact source hashes differ from the old 360 fixtures and ten external files, but attack families remain familiar.
- First-use weighted label agreement: 12/18 (66.67%), three false accepts against AI labels. Frozen v2/v3 ML replay: 11/18 (61.11%), three false accepts each. This is offline scoring of identical fresh detector observations, not a live ML throughput benchmark.
- Native SHAP additivity residual maximum: 0.0000153 (v2), 0.0000458 (v3). Arithmetic consistency does not establish valid ground truth, causal explanations or calibrated risk.
- Fixed Python weak-hash context detection for password-named functions with generic arguments; ordinary checksum negative controls pass.
- Fixed package lifecycle network-to-shell detection even with no dependencies. This is bounded static pattern detection, not complete shell semantics or arbitrary dataflow analysis.
- Changed services rebuilt and deployed. Full code-security suite: 70 passes. Full CipherGuard suite: 44 passes. Existing hook utility suite: 121 passes, including 63 hook tests. PostgreSQL extra integration case: one pass. Counts across latest component suites total 729 Python passes; not a single new full-suite command. Nine prior browser cases remain separately dated.
- Post-fix development retest: all 18 finalize, label agreement 14/18 (77.78%), one false accept (UNLICENSED policy context). Weak-hash proposal now Review 78.75; install pipeline now Reject 0.0.

## Honest limits for the paper and demonstration

The first-use cohort is a prospective AI-authored, AI-labelled pilot. It is not an independently human-labelled external final benchmark. The assistant authored the fixtures and labels; exact-content nonduplication is not family separation. The two previous real upstream projects were already scanned; they cannot become untouched by relabelling them. Once pilot errors were inspected and fixed, its post-fix run became a development retest.

No person has attested the labels. No human review has been invented. Independent human validation and a representative new external project/family holdout remain unfulfilled if those claims are required by the paper. A human may still complete the untouched review forms later; AI review does not satisfy --require-reviewed.

The normal deployment remains weighted. No model was retrained or promoted during this wrap-up. ML does not recover defects absent from detector features: both models accepted the missed weak-hash and install cases on the original frozen observations. Do not replace earlier 66.67% or 83.33% figures with a favourable value from a different cohort without qualification.

Remaining observed errors include benign Markdown Review, precedence instruction Reject vs AI Review, detected shell injection Review vs AI Reject, and acceptance of UNLICENSED vs AI Review. A Review denies the configured pre-acceptance write; exact tri-class accuracy and gate success are different quantities. No claim of complete production security is supported.

No upstream or malicious fixture was executed, no credential files were exported, no remote push was performed, and no native VS Code screenshot is claimed.
