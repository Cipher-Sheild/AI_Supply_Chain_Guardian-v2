# Predictive Trust Engine: design and ML implementation brief

Prepared 12 October 2026 from the supplied project reference and current repository. This is a newly consolidated engineering brief, not a recovered original Synopsis or university submission. The user-supplied reference is preserved unchanged in `reference/PROJECT_DOCUMENTATION_2026-10-11.md`; its completion statements stop at Checkpoint 1. Current evidence is in `STATUS.md` and `checkpoint-2/VERIFICATION.md`.

## Project purpose and boundaries

AI Supply Chain Guardian assesses software artifacts before developer acceptance or commit. Seven specialist detectors cover dependency hallucinations, insecure code, secrets, Docker/Compose risks, GitHub Actions risks, license uncertainty/conflicts, and prompt injection. The Trust Engine is the eighth service: it routes, dispatches, fuses, explains and persists results; it does not duplicate detection.

The contribution proposed by the project is pre-acceptance integration and artifact-level trust assessment. A learned scorer is a planned extension whose value must be measured, not assumed. Do not claim research novelty or predictive calibration merely because XGBoost is present.

## Existing Trust Engine

- FastAPI is the public entry point. Capability-based routing selects relevant detectors per file; asynchronous HTTP dispatch runs them in parallel with bounded capacity and deadlines.
- Shared versioned AgentResult contracts retain findings and evidence. Missing, unsupported, failed or pending checks are uncertainty, not clean results.
- The default scorer is `WeightedSumScorer` in `services/trust_engine/app/scorers.py`. `Scorer.score(state, total_risk)` returns a finite score from 0 to 100; `fuse(state, scorer=...)` is the model integration seam.
- Hard overrides remain outside the scorer. Coverage, pending/error/unresolved status, severity and license-review gates remain authoritative. A model cannot override a required Reject or promote an uncertain scan to Accept.
- Default decision bands are Accept at 80+, Review at 50–79.99, Reject below 50, subject to policy gates. Ordinary license conflicts impose a Review floor; explicit organization denylists supply a license rejection override. Combined numerical risks can still Reject. Go remains partial coverage.
- Single and batch APIs, recorded per-file outcomes, history, audit PDFs, CLI/pre-commit and a minimal dashboard are implemented. SQL scan snapshots preserve original outcomes across scorer changes. PostgreSQL is configured for Compose; local SQLite behavior is tested.
- Prompt callbacks update scans atomically. Durable prompt job/result delivery and overdue finalization are implemented. Feature observations use initial/callback phases; a callback event can remain provisional when other callbacks are pending.
- No trained predictive scorer or SHAP integration exists. Full Docker/PostgreSQL/live-model verification and remote CI remain outstanding; local implementation tests are a different level of evidence.

## Stepwise scope for the Trust Engine ML developer

1. Read `ML_HANDOFF.md`, `CONTRACT_V1.md`, the scorer/fusion/feature code and current status. Keep detector input/output contracts and existing safety gates intact. Prefer new ML modules and a Scorer implementation; coordinate any additional API or explanation changes explicitly.
2. Define the prediction target and labeling rubric before training. Choose artifact risk/severity or a decision-risk target, and document how it maps to a 0–100 trust score. Binary benign/malicious labels alone do not define a meaningful middle Review band or a calibrated trust score.
3. Build an independently labeled artifact corpus with provenance and grouped splits. Detector outputs and the existing Trust Engine decision are features/comparison outputs, never ground truth.
4. Run samples through the relevant detectors using the corpus runner. Join final feature observations to labels by request_id and file index; verify every join and preserve missingness.
5. Add deterministic feature preparation, schema/version validation and reproducible training. Exclude outcome/decision fields, IDs and incidental timing from predictors by default to avoid learning the existing decision or environment. Assess leakage and any exception explicitly.
6. Train a simple comparison model and constrained XGBoost candidate. Apply monotonic constraints only to features with an established direction: greater risk must not increase trust. Model missing checks explicitly; preserve external uncertainty gates regardless of learned behavior.
7. Compare with the weighted baseline on the same held-out artifacts. Report false accepts, precision/recall/FPR, confusion matrices, calibration where probabilities are claimed, and per-artifact-type results. Run agent ablations; do not tune on the final test set or promote a worse model by default.
8. Integrate the chosen model through the Scorer seam with an explicit model/feature version, startup validation, bounded inference and a safe weighted fallback when loading/inference fails. Add regressions proving overrides, uncertainty gates, finite bounds and per-file/callback behavior remain intact.
9. Add SHAP for the trained model. Identify its baseline and output space; group feature contributions by detector for display, retain a category for global features, and show policy overrides separately. SHAP describes the model's output, not causation or the final policy-adjusted decision. Do not overwrite original detector evidence.
10. Deliver training/evaluation scripts, corpus manifest and labeling rubric, split definitions, model artifact and metadata, integration tests, results against baseline, explanation examples, and updated documentation. Report model limitations and deployment checks still needed.

## Answer to the dataset question

There is currently no independently labeled fused artifact dataset ready for Trust Engine training. The reference describes existing CipherGuard package-level benchmark records and small service fixtures, but these are not a ready-made artifact-level fused corpus. Historical benchmark counts/results must be checked against their underlying data before reuse. The checked-in host smoke observations are demonstration inputs, not a training dataset.

Build clean controls, single-risk cases, mixed-risk cases, ordinary license conflicts/unknowns and unsupported or uncertain cases across code, dependency manifests, Dockerfiles, Compose, workflows and Markdown. Use reviewed real artifacts where licensing permits plus constructed cases with known planted risks. Record source/license, author or generator, source group, label, rationale and reviewer in a separate provenance table. Use fabricated credentials only; do not add real leaked secrets.

Start with a few hundred reviewed artifacts as a pilot, then expand according to coverage and learning curves; this is a proposed starting scale, not a proven sufficient sample size. Keep related variants, copied templates and samples from the same source repository/generator together across splits. Ask a separate reviewer to author or adjudicate the held-out set. Do not duplicate the same case under several filenames and treat it as independent evidence.

Only relevant detectors run for an artifact. Forcing every artifact through all seven creates meaningless unsupported results. Unselected or unavailable measurements stay null, not zero. Distinguish clean successful zero findings from a detector that did not run.

`scripts/run_labeled_corpus.py` accepts CSV/JSON/JSONL manifests with `sample_id`, `path`, `label` and optional `artifact_type`. Paths resolve relative to the manifest. It submits artifacts, waits for final results and writes request-ID/label/error mappings; it neither invents labels nor trains a model. Keep richer provenance separately and join by sample_id. Feature JSONL excludes raw artifact content and unrestricted evidence. For pending scans, select a final callback observation with no selected pending agents; timeout/error remains uncertainty. Check join completeness before training.

## Documents and branch availability

- `reference/PROJECT_DOCUMENTATION_2026-10-11.md`: closest supplied comprehensive source reference, preserved verbatim; historical completion ledger.
- `ML_HANDOFF.md`: exact scoring seam, feature privacy and integration constraints.
- `CONTRACT_V1.md`: detector contract and policy requirements.
- `STATUS.md`, `checkpoint-2/VERIFICATION.md`: current build status and proof limits.
- Published baseline: `codex/checkpoint-1-contracts`, commit `bbd4980`.
- Checkpoint 2 and its corpus runner are on local `codex/checkpoint-2-completion`; publication was rejected because GitHub credentials lack workflow permission. Do not assume the teammate can pull this branch until publication succeeds or a repository snapshot is supplied.

The original university Synopsis/Final Documentation is not identified as a supplied standalone source in this handoff. This brief must not be presented as that original document.
