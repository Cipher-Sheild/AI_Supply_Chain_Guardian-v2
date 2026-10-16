# Final local verification — 12 October 2026

No final-run code is pushed. This is local/team implementation evidence, not a production certification. The original Checkpoint 1/2 reports are historical snapshots.

## Reproducible checks

| Check | Result and scope |
|---|---|
| Clean runtime `python scripts/setup_local.py` | Python 3.12 environment created under `.data/venv`; CPU dependencies, training stack and pinned embedding snapshot installed; `pip check` passes |
| All eight suites via `scripts/verify_checkpoint1.py` | **439 passed, no skips**; latest logs/results in `../final-validation-clean/`; migrated scratch TEST_DATABASE_URL enabled the actual PostgreSQL test |
| `python -m pytest scripts/tests -q` | **16 passed**: CLI bounds/outcomes, corpus provenance/hash/groups, returned credential hygiene, percentiles and label mapping |
| Contract/runtime sync `--check` | Pass; detector contract 1.0, operational helper copies match |
| Python compileall / git whitespace check | Pass |
| PostgreSQL 16.15 migrations and seed | Pass against temporary loopback server; restart/fractional score/two-store row-lock integration passes |
| Redis 7.0.15 | Temporary loopback service used by native HTTP stack; cache is not scan-history authority |
| Pinned MiniLM snapshot | Downloaded and real 384-dimensional encoder loaded; revision and file hashes recorded |
| Local Ollama judge | Valid typed JSON verdict observed; 55.96-second check while other requests active. Bounded guardian-judge alias, JSON/context/output/thread limits and successful-only exact TTL cache added; no quality or three-second claim |
| Native HTTP schema audits | All seven detector responses CONFORMS; initial weighted stack uses PostgreSQL/Redis and all eight readiness checks succeeded at that snapshot |
| Optional model HTTP smoke | Seven artifact types completed/retrieved; trained scoring path active and all seven schema audits conform; see `../final-validation-ml/host-smoke.json` |
| Actual batch/history/PDF/redaction/bounds HTTP | Pass, including learned per-file metadata and fabricated vendor credential rejection; `../final-validation-ml/interfaces-http.json` |
| Same-origin proxy | Verified backend response through `/api/health`; one recorded readiness response is 503 due registry probes, not falsely called healthy |
| Frontend build and npm audit | Pass; Vite 8.3.4/react plugin 6.1.2, unused Tailwind tooling removed; audit zero current findings |
| VS Code build/package/audit | Pass; local VSIX produced; editor interaction unverified; package license/publisher choice remains owner's publication decision |
| Compose `config --quiet` | Pass using `/dev/null` env and throwaway callback token; not an image build/start proof |
| Docker daemon | Permission denied; no container deployment claim |
| Browser/editor GUI | No visual interaction proof. Prior automatic browser approval rejection respected; API/build checks do not substitute for GUI checks |

Direct container requirements are pinned; `evaluation/trust_model/runtime-python312-linux.lock.txt` captures the clean local resolved environment, without hashes/cross-platform guarantees. Native tools are copied from matching host versions and hashed in .tools/manifest.json; this does not claim independent release attestation for those existing binaries. No private `.env` values are printed or staged.

## Dataset and model

360 project-authored synthetic artifacts: train 180, validation 90, grouped test 90; 120 per label. Labels precede detector execution; no independent human review is claimed. Construction checks caught duplicate content and malformed workflow YAML. Corrected workflow and Markdown samples were recollected; merge/training checks bind each final response to manifest SHA-256 and preserve labels/request IDs.

Feature observations advance to 2.0; model input schema guardian-risk-v2 uses 98 monotonic risk features. Reconstructed training observations exclude outcomes, content, identities as predictors and timing; unknown timing is null. The initial collected version-1 observation log is retained as historical evidence, not silently consumed as version 2.

Candidate depth is selected using validation, not test. On the 90 grouped synthetic test samples:

| Metric | Weighted | XGBoost candidate |
|---|---:|---:|
| Policy decision accuracy | 77.8% | 77.8% |
| MAE against 100/65/0 engineering anchors | 19.58 | 14.83 |
| Non-Accept labels returned as Accept | 5 | 0 |
| Clean labels returned as Review | 0 | 10 |

Native/library TreeSHAP maximum difference is 0; tested observed-feature monotonicity violations are 0 across 3360 perturbations of all 90 test rows. Full confusion/per-type/ablation results are in `evaluation/trust_model/results.json`. Related templates and common author remain substantial limits. These are not probability calibration, external generalization or statistical independence claims. Weighted remains the default; candidate is optional and not production-promoted.

## Material limits and next evidence

Docker daemon permission, manual dashboard/editor checks and independently reviewed external data are still required for their corresponding claims. Scanner recall, external registry/digest/CVE behavior, cold/warm/load p50/p95 and container crash/restart need additional measured scenarios. API admission/timeout bounds are implemented; they are not a latency guarantee. Public multi-tenant auth/TLS/retention and specialist Go/GitLab/full dependency graph support remain outside delivered local scope. Hardening suggestions are never called build-verified fixes.

Current project documentation: `docs/FINAL_PROJECT_DOCUMENTATION.md`, SRS, SDD, TEST_PLAN, USER_MANUAL and DATA_LABELING_GUIDE. The user will supply a new repository when publication is desired.
