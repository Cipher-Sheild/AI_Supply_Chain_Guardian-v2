# Final local implementation notes — 12 October 2026

No remote push is authorized for this run. The user intends to create a new repository.

Changes after Checkpoint 2 include synthetic corpus construction/label rationales, a grouped training pipeline, monotonic XGBoost scoring, native TreeSHAP/API/dashboard/PDF explanations, model version/checksum validation, weighted fallback, a pinned locally downloaded MiniLM snapshot, native launch/setup scripts, and an explicit-command VS Code extension. The default remains weighted until independent model validation.

The original Semgrep CLI repeatedly exceeded the request budget. The pinned OSS native engine scanned the same probe in about 0.24 seconds while CLI paths took approximately 6–8 seconds in this host. All rules/severity mapping remain; native warning envelopes use severity rather than level. Partial parsing now explicitly reduces coverage. Timed-out process groups are killed. Initial failed test/corpus attempts prompted these changes; do not characterize them as passes.

Fusion now ignores explicitly unselected records and holds unexecuted expected checks at Review. Feature observation schema remains version 1.0; additive public scoring metadata is persisted with snapshots.

Corpus quality checks caught cross-split duplicate content and malformed workflow permissions before training. Fixed workflows were recollected and replace earlier malformed responses by sample_id; submitted hashes are checked by training. Labels are authored by construction, not detector decisions, but no independent human review is claimed.

PostgreSQL 16.15 and Redis 7.0.15 were downloaded/extracted under /tmp and bound only to loopback for local integration checks without administrator changes. PostgreSQL migration, seed and distributed row-lock test passed. This is not Docker image/Compose verification. Docker daemon access remains denied, and the prior browser approval rejection remains respected.

Feature observations advance to version 2.0 with five fixed numeric category-group counts per detector. These distinguish dangerous execution/data access from review-level patterns sharing the same severity. No arbitrary categories/content are logged. Detector contract remains 1.0; old version-1 observations are historical and must not be silently interpreted as version 2. Training reconstructs version-2 features from final detector responses, not labels.

The local Llama backend returned a valid typed verdict in a 55.96-second check while other jobs were active; timeout cases remain recorded uncertainty. A bounded guardian-judge model alias avoids default CPU oversubscription. Exact successful single-vote classifier responses use a bounded TTL cache; quorum votes bypass cache and errors are not cached. Markdown uses separate header/body paragraphs and is fully recollected with matching hashes. The corpus remains related synthetic templates, not independent examples.

Callback redirects no longer acknowledge successful delivery. The regression confirms no token-bearing redirect is followed and the journal retains unresolved delivery rather than silently discarding it. SHAP groups explicitly identify unselected detectors as missingness contributions, not evidence of a completed scan.

Clean workflow examples now use actual SHA refs obtained with git ls-remote from official actions repositories, instead of a syntactically valid fictional SHA. Those files were recollected and the corpus/model metadata regenerated; labels and detector algorithms were not tuned from test results. Official ref provenance is recorded in the corpus directory.
