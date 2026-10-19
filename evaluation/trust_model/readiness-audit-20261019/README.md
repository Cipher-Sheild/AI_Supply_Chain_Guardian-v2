# ML readiness audit — 19 October 2026

## Decision

Do not promote the learned scorer to production. Keep weighted enforcement and ML advisory comparison. No model was retrained on the ten reviewed labels, and no safety gate or decision threshold was weakened.

## What was measured

The same ten previously inspected, project-team reviewed upstream files were submitted to the current weighted API. Source hashes were checked. Both scorers were replayed offline against each identical final detector response, eliminating differences caused by separate live detector runs. These are diagnostic development replays, not a new independent benchmark. Detailed results and scan IDs are in the two fresh-responses.jsonl files and results.json files alongside this document.

Before repair, weighted and v4 verdict agreement were 30% and 30%. After repair, both are 40% (4/10). This is an end-to-end detector improvement, not evidence of improved learned-model generalisation. The v4 synthetic development result remains 83.33% on the already inspected 90-case cohort.

This ten-file cohort has eight Accept and two Review labels and no Reject labels. Zero false accepts on it does not establish malicious-input recall, rejection performance or production safety. Reviewer identity was not independently authenticated. It covers two repositories and three source formats, not all seven detector domains.

## Implemented repair

The licence matcher previously required the descriptive MIT License heading. A pinned canonical complete MIT body without that heading is now recognised. Exact substantive clause comparison remains mandatory. Added regression checks preserve Review for added restrictions, altered permissions and missing disclaimers. All 44 licence service tests passed. The shared live licence detector was rebuilt and restarted; both deployments use it. Both upstream MIT files now receive Accept from both scorers.

## Root causes remaining

Five of ten labels remain unreachable even if their desired target score is substituted: the deterministic gates still require Review. The high raw scores on several of these cases show that retraining the trust scorer alone cannot solve the disagreements.

- Ordinary comments in sampleproject __init__.py and test_simple.py trigger strong prompt classifier signals (approximately 0.999 probabilities), despite contextual judgment not confirming an attack. This indicates domain/calibration problems when a classifier trained on direct prompts is used on source comments. It does not justify simply discarding disagreement.
- Both README files have prompt-injection findings and partial coverage. Clearing only a numeric trust score cannot establish full inspection.
- Flask db.py has a code-security SQL injection finding. Its implementation and the supplied-text human rationale need adjudication before changing either the finding or label.
- Flask tutorial __init__.py is labelled Review but scores Reject. It contains a reported credential assignment and prompt warnings. This is a candidate for score calibration only after broader, separately reviewed development data exist.

## Requirements before a production claim

1. Build a substantially broader, licence-checked corpus with benign documentation/comments and malicious indirect-injection counterparts; preserve attribution, hashes and repository-family splits. Keep already inspected files in development only.
2. Have reviewers adjudicate detector findings against a written supplied-text scope; retain disagreement and rationale. Do not change labels just to match predictions.
3. Retrain/calibrate the prompt candidate classifier on representative development data. Select changes using validation data and evaluate both false alarms and missed attacks. Validate truncation and coverage handling independently.
4. Collect final detector observations for the expanded cohort, then train the trust scorer with group-separated training/validation and a genuinely untouched final cohort. Compare weighted and ML on identical observations; report per-class precision/recall, macro F1, confusion matrices, score error, uncertainty and per-domain support.
5. Preserve authoritative safety rules, fail-closed behaviour and SHAP additivity checks. Test actual malicious cases across all detectors, not just benign demos.
6. Separately verify deployment security, tenant isolation, failure recovery, concurrency/latency, monitoring, rollback and retention. Accuracy alone cannot establish operational readiness.

No benchmark or report from earlier work was overwritten. The demonstration workspace and existing Copilot records are retained. New scans are identifiable under readiness_audit. Production promotion remains false.
