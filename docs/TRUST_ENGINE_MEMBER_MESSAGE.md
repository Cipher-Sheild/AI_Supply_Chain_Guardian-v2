You're right: the Trust Engine currently uses hard overrides plus a weighted scorer. Your piece is the predictive scoring and model explanation layer within the Trust Engine; the routing, detectors, persistence and callback lifecycle already exist. XGBoost and SHAP are not implemented yet.

Please proceed in this order:
1. Read the attached project reference, design brief, ML_HANDOFF.md and CONTRACT_V1.md. Implement through Scorer.score(state, total_risk); preserve hard overrides and all coverage/uncertainty floors.
2. Define a labeling rubric and prediction target. Build an artifact-level dataset with clean, risky, mixed and uncertain cases, labeled by construction or human review—not by detector verdicts. Binary benign/malicious labels alone do not define our Review band or 0–100 score.
3. Run each artifact through its relevant detectors, not all seven. The corpus runner records supplied labels and request IDs. Join only final feature observations; null means not run/unavailable, never clean zero.
4. Keep related samples together in grouped splits and use an independently authored/reviewed held-out set. Record provenance and label rationale. Exclude existing decisions/scores-as-target, outcome fields and identifiers from predictors to avoid leakage.
5. Train and compare a constrained XGBoost scorer against the weighted baseline. Preserve monotonic risk behavior and report false accepts, calibration, per-type results and agent ablations. Keep the baseline if the model does not improve the measured tradeoff.
6. Integrate model loading/versioning and safe fallback; test that a model cannot override Reject or promote uncertain coverage to Accept.
7. Add SHAP explanations for the trained model, group contributions by detector and display policy overrides separately. Deliver reproducible training/evaluation code, model metadata, tests and updated docs.

Data answer: we do not currently have a ready, independently labeled fused artifact corpus. Existing CipherGuard package benchmarks and small detector fixtures are useful source material but are not that dataset. Start with a reviewed pilot of a few hundred artifacts, then expand based on coverage; this is not a guarantee of adequate training size. Use fabricated secrets and licensed source material, and keep provenance.

I'm sending the unchanged comprehensive project reference plus a newly consolidated Trust Engine design brief. The reference's completion status stops at Checkpoint 1; the brief explains the current build. It is not the original university Synopsis. Published baseline: codex/checkpoint-1-contracts at bbd4980. Checkpoint 2/corpus runner are local until the GitHub workflow-permission push blocker is resolved; don't assume those files are already available remotely.
