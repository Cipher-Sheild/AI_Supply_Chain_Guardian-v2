# Final local status — 12 October 2026

The user authorized completing this project locally and explicitly forbids pushing this run. No final-run changes are uploaded to the old repository. Current implementation and measured results are in [FINAL_PROJECT_DOCUMENTATION.md](FINAL_PROJECT_DOCUMENTATION.md) and [final verification](final-validation/VERIFICATION.md).

**439 service tests pass in the clean project-local Python environment, including the PostgreSQL integration and real learned-model/SHAP tests; no service test is skipped.** Sixteen script tests pass. Frontend and VS Code builds/package pass; frontend npm audit reports zero vulnerabilities. Seven detector HTTP schema audits and native PostgreSQL/Redis/embedding/judge checks are documented separately. Browser/editor interaction and Docker container execution remain unverified.

| Feature | Current delivery |
|---|---|
| Seven detectors, routing and deterministic fusion | Implemented and locally validated; declared scope limits remain |
| SQL history / durable prompt jobs / atomic callbacks | Implemented; local PostgreSQL migration/row-lock and HTTP integration pass |
| Batch/per-file API, CLI/pre-commit, dashboard/history/PDF | Implemented; API/build checks pass; manual GUI check remains |
| VS Code command | Implemented and VSIX packaged; explicit invocation, not universal AI-provider interception |
| Dataset / labels / grouped training | 360 constructed artifacts, provenance/hash/rationale checks; no independent human review |
| Constrained XGBoost | Trained, versioned, checksum/schema validated and integrated; optional candidate, weighted default |
| Exact TreeSHAP | Native/library agreement and additivity checked; API/per-file/dashboard/PDF metadata separates policy gates and unselected missingness |
| Model evaluation | Grouped synthetic test n=90: both accuracies 77.8%; false accepts weighted 5 vs XGBoost 0; 10 clean samples moved to Review |
| Model quality/promotion | No production promotion, external held-out benchmark or calibrated probability claim |
| Operational verification | Native services/PG/Redis/models checked; Compose parses but Docker daemon access remains denied |

Final additions repair Semgrep CLI startup overhead via the pinned OSS core, terminate scanner process groups on timeout, mark partial parsing incomplete, ignore explicitly unselected fusion records, and prevent unexecuted clean results from Accept. Returned credential-shaped values are masked without dropping evidence structure. Exact valid single-vote judge responses have bounded TTL caching; failed replies/quorum votes do not reuse the cache.

Feature observations now use version 2.0 (five fixed numeric category groups added per detector) and model schema guardian-risk-v2. Detector contract remains 1.0. The previous protection of scorer/fusion/feature files applied to Checkpoint 2; the user's final ML implementation authorization necessarily adds to those files, as described in the final documentation.

Outstanding evidence/scope: independently reviewed external data and held-out attacks, real-world accuracy/calibration/load results, browser/editor interaction, complete Docker image/Compose/restart/build verification, public auth/TLS/tenant isolation/retention, and specialist Go/GitLab/full dependency graph support. Local implementation completion does not imply a security guarantee or unrestricted production readiness.

---

## Historical Checkpoint 2 ledger (superseded completion counts/model status)

The following dated audit ledger preserves what was known before the final local ML run. Its old no-model and unchanged-file statements describe that checkpoint only.

# Checkpoint 2 status — 11 October 2026

Checkpoint 1 is published as `bbd4980` on `codex/checkpoint-1-contracts`. Checkpoint 2 is implemented on `codex/checkpoint-2-completion`. “Fixed locally” describes passing correctness regressions, not a production deployment guarantee. Docker access is still denied. The original audit and file inventory remain in `audit-2026-10-11`; see `checkpoint-2/VERIFICATION.md` for commands and limits.

All eight local suites pass: **424 tests**, with **one PostgreSQL integration test skipped**. Script tests cover CLI gates, invalid scores, percentile boundaries and label mapping. A fresh Trust Engine environment has a separate passing suite and clean pip dependency check. Real host HTTP processes completed seven artifact types and seven detector schema audits; these used SQLite and a deliberately disabled judge, with missing local embedding/ScanCode capabilities reported as degraded. No trained predictive model or SHAP was added.

Test abbreviations TE/CG/LC/PI/CS/DS/SD/WF refer to `services/<service>/tests`; existing Checkpoint 1 names and new checkpoint2/readiness/cache/outbox tests are retained. Runtime code, deployed containers and empirical detection quality are different levels of evidence.

| ID | Status | Passing evidence or audit baseline | What remains |
|---|---|---|---|
| F01 | fixed locally | TE `test_expected_unusable_status_never_accepts`, `test_required_uncertainty_never_accepts`, `test_response_reports_achieved_coverage` | Deployment verification |
| F02 | fixed locally | LC `test_unknown_zero_confidence_is_unresolved`; TE required license-review gate at zero confidence | License identification coverage remains conservative |
| F03 | fixed locally | CG `test_clean_dependencies_emit_evidence_not_findings` and TE `test_clean_package_observations_do_not_reduce_trust`: 1, 9, 21 packages | Independent live registry calibration |
| F04 | fixed locally | DS completion/tool-outage tests; host HTTP Hadolint/Trivy scan and schema audit | Container/CVE-image integration unverified |
| F05 | fixed locally | Seven detector HTTP responses CONFORMS in checkpoint-2/host-smoke.json; recursive schema tests | Compose audit still unverified |
| F06 | fixed locally | LC shipped-default/explicit-deny/AND/OR regressions; TE authoritative overrides | Ordinary license Review is a minimum floor; score bands can still Reject combined risks |
| F07 | fixed locally | TE capability routing/unsupported coverage regressions; CS real extended-suffix Semgrep tests | Go rules, GitLab, pyproject/Pipfile specialist support intentionally partial |
| F08 | fixed locally | TE capability tests validate canonical request/options, filename precedence and request types against matrix | Full deployed dispatch verification |
| F09 | fixed locally | CG manifest-integrity tests; LC malformed/unsupported/empty manifest tests | Full dependency/lockfile resolution remains unsupported |
| F10 | fixed locally | SD context-confirmed secrets, weak password, placeholder and environment-reference tests; confidence/location round trip | Broader corpus calibration |
| F11 | fixed locally | DS final-stage/last-USER/Alpine and shell-less-image regressions; suggestions never claim build verification | Actual build-verification feature remains absent |
| F12 | fixed locally | DS image reference tests: registry port, digest, prior stage aliases; non-Hub/digest unverified regressions | External-registry/digest verification remains explicitly unverified |
| F13 | fixed locally | PI `test_strict_judge_contract`, tied votes, failed quorum and two-of-three quorum | Live model quality/latency and durable delivery |
| F14 | partial | CS real warm-up readiness and timeout cap; TE global queue deadline and cancelled-worker-slot regression; host timings | No production p95/load guarantee; some host samples exceed the 3-second target |
| F15 | fixed locally | Bounded 512-entry TTL fallbacks and bounded Redis pools; no cached transport failures; DS TTL/size regression | Redis-backed deployment/recovery still unverified |
| F16 | fixed locally | CS equal JS/Python severity fixtures; actual JS rule suite; extended-suffix scans | Optional language confidence calibration left to teammate |
| F17 | fixed locally | WF malformed expected workflow and scanner crash regressions return error, not empty fail/stub | GitLab support remains partial |
| F18 | fixed locally | LC full expression tests cover AND/OR precedence, nesting, unknown nodes, WITH, invalid syntax and ScanCode expression preservation | Unsupported license exceptions conservatively require review |
| F19 | fixed locally | TE finite confidence/score bounds, pending callback identity, response identity mismatch, missing expected results and API type validation | Authenticated deployment threat model and load limits are separate work |
| F20 | implemented; local tests pass | PI journal restart/lease/retry and provider-close tests; TE overdue/late-pass regression | Live judge and container crash/restart delivery unverified |
| F21 | implemented; local tests pass | TE atomic concurrent updates, stored final results/history, historical per-file outcomes preserved | Distributed PostgreSQL row-lock test is defined but skipped locally |
| F22 | implemented; local tests pass | Normalized SQL writes/fractional scores/reopen tests; Alembic offline SQL passes; migrate/seed Compose dependency | Live PostgreSQL migration/writes and container startup unverified |
| F23 | fixed locally | Six unused configs removed; consumed Prompt/License config retained; README/service/evaluation/runtime docs reconciled | Historical outputs are dated snapshots; model calibration remains separate |
| F24 | partial | Real host readiness identifies tools/models/registries/storage; all scanner images non-root; Compose env/resources scoped and config validates | Images/startup/resource behavior unverified; production auth/TLS/tenant isolation absent |
| F25 | implemented; local tests pass | Typed batch/per-file bounds/history/PDF API test; CLI exit/threshold tests; React build; same-origin proxy and pre-commit hook | Browser interaction blocked by approval review; Compose dashboard unverified |
| F26 | partial | Exact direct dependency pins, CI eight suites/contract+runtime drift/PG test; correct percentiles/time-to-final; corpus mapping tests | Remote CI and heavy model/baseline runtime not yet verified; direct pins are not a full transitive lock |



| Promised feature | Current status | Evidence / remaining |
|---|---|---|
| Eight HTTP services; router/orchestrator/fusion | host HTTP verified | Seven artifact types and recursive detector audit; Compose still unverified |
| Deterministic capability routing and uncertainty gates | fixed locally | Regression suites; Go/GitLab/unsupported dependency formats remain partial |
| Seven detectors | implemented with limits | Real Semgrep/Hadolint/Trivy and registry smoke; no independent corpus/model-quality validation |
| Weighted Trust Score and policy floors | fixed locally | Existing fusion seam unchanged; ordinary license Review floor, explicit denylist override |
| Versioned portable detector evidence | HTTP verified | All seven schema audits CONFORMS; detector schema remains 1.0 |
| Public multi-file API and per-file outcomes | implemented | Typed bounds/history/PDF tests; outcomes persist instead of being rescored on reads |
| PostgreSQL scan/execution/finding/routing/score history | implemented; PostgreSQL unverified | SQLite transactional/reopen tests pass; offline migration SQL passes; CI integration defined |
| Prompt async jobs/callbacks/timeouts | implemented | Bounded durable journal/replay, atomic updates, overdue final error; live container restart unverified |
| CLI and pre-commit | implemented | Meaningful final-state/threshold exit codes and regression tests; server required |
| Dashboard/history/PDF | implemented | Build and API checks pass; browser access declined; container UI unverified |
| Sanitized training observation log | schema unchanged | JSONL privacy whitelist; named volume added; operator manages retention/backups |
| Scorer plug-in seam | unchanged | scorers.py/fuse()/features.py match Checkpoint 1 byte-for-byte |
| Trained predictive model / XGBoost / SHAP | absent by design | Teammate responsibility: independently labeled corpus, grouped splits, held-out comparison |
| Labeled-corpus submission/join runner | implemented | Preserves supplied labels, waits for final results, writes request IDs/errors; generates no labels |
| Docker hardening build verification | absent | Suggestions always identify their unverified status |
| Production authentication/TLS/tenant isolation | absent | Current deployment is local/team use; callback authentication is implemented |
| Three-second target / production latency guarantee | unproven | Operational deadlines/capacity exist; smoke timings are not p95/load validation |
| Dependency pins and CI | configured; remote execution unverified | Exact direct pins; not a complete transitive lock; optional model/baseline execution unverified |

Feature privacy whitelist/schema and scorer/fusion implementation are unchanged. Public ScanResponse adds typed `per_file`; SQL snapshots also retain these outcomes. Multiple callback rows can be provisional: training must select a callback row without selected pending agents. Scan snapshots and prompt journal contain submitted content; SQLite/journal files use 0600 permissions and Compose volumes require protected retention/backup.

## Checkpoint 2 progress
Group 1: implementation adds a process-wide dispatch gate, 9-second dispatch deadline including queue, per-agent timeout settings, body/admission bounds, non-root images and scoped Compose environment/resources. Semgrep background warm-up uses a real rule-bearing scan with a separate 90-second startup budget; health remains degraded until success. Registry readiness probes and model/tool checks are explicit. Cache fallbacks have TTL and entry bounds. Local regression results will be consolidated in checkpoint-2/VERIFICATION.md; production latency and container readiness are not confirmed without Docker.

Group 2: every scan now persists through ScanStore. Compose uses PostgreSQL; local development uses durable SQLite. Snapshot/routing, normalized per-agent executions/findings, scan lifecycle and fractional trust score commit together. Alembic offline SQL generation and restart/history persistence regressions pass. Compose migration/seed dependency is configured; live PostgreSQL verification remains blocked.

Group 3: callbacks update under a database row lock (Redis WATCH for legacy test stores); overdue records become final error/Review and late callbacks cannot replace that outcome. Prompt jobs and resolved callback results persist in a bounded leased SQLite journal, retry across restart and retain no callback token. Named volumes retain the journal and feature log. Local atomic-update/late-callback/outbox-restart regressions pass; crash/restart under Compose is unverified.

Group 4: public `/analyze/batch` validates count, unique filenames, 256 KiB per-file and 1 MiB aggregate content; 2 MiB body admission and process capacity apply to all POSTs. Responses add per-file outcomes. CLI waits for final status, applies a configurable threshold and meaningful exit codes; the pre-commit hook invokes it. React dashboard builds with a same-origin `/api` proxy, polling/history/evidence/PDF export. Browser interaction is still to be checked; Compose UI is unverified.

Group 5: direct Python dependencies and frontend dependencies are pinned; CI defines all eight isolated suites, contract/runtime drift checks, script tests, frontend build and PostgreSQL integration. Nearest-rank percentile and separate time-to-final/error reporting are implemented. The corpus runner preserves caller labels and records server IDs; regression tests cover label joining and CLI decision gates. Trust Engine has a fresh clean-environment passing run. Heavy optional model/ScanCode clean-environment execution and remote CI remain unverified.

Group 6: removed six unused YAML configurations; retained only consumed Prompt/License settings and removed unused switches. Root/service/evaluation/runtime documentation now distinguishes implemented behavior from historical comparisons and targets. No trained predictive model or SHAP was added.
