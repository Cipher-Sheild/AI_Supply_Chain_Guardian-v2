# Checkpoint 2 verification — 11 October 2026

Checkpoint 1 was re-verified (401 passing) and pushed as `bbd4980`. Checkpoint 2 completes the six implementation groups; production/container/model proof remains limited as stated below. Detailed finding/feature tables are in ../STATUS.md and changed files in FILE_CHANGES.md.

## Commands and evidence

| Command / check | Result | Evidence / limits |
|---|---|---|
| `/tmp/ptic-checkpoint-venv/bin/python scripts/verify_checkpoint1.py` with `VERIFY_OUTPUT_DIR=docs/checkpoint-2` | 424 passing, one PG test skipped | test-results.json and service logs; this environment inherits system packages. Changed suites were rerun after relevant fixes. |
| Fresh venv, install `services/trust_engine/requirements.txt`, `python -m pytest tests -q` from that service | Passing; one PG test skipped | trust-engine-clean-tests.txt; no inherited system packages |
| Fresh environment `python -m pip check` | No broken requirements | Trust Engine dependencies only |
| `pip install --dry-run -r services/license_compliance/requirements.txt --report ...` | Resolver succeeds | license-dependency-resolution.json; no ScanCode runtime execution proved |
| `python -m pytest scripts/tests -q` | 14 passing | script-tests.txt; labels in test fixtures are synthetic stubs, not a generated corpus |
| `npm ci --prefix frontend`; `npm run build --prefix frontend` | Build succeeds | Pinned package-lock; browser visual/interaction checks unverified |
| `python scripts/sync_contracts.py --check` | Pass | Version 1.0 detector copies unchanged |
| `python scripts/sync_runtime.py --check` | Pass | Standalone build contexts match canonical operational helpers |
| `git diff --check`; Python compileall | Pass | Syntax/whitespace checks |
| Compose `config --quiet` using `/dev/null` env file and a throwaway callback token | Pass | Configuration parses; does not build/start images or print real environment values |
| Alembic `upgrade head --sql` with a deliberately nonexistent DB host | Pass | Regression verifies no connection and fractional-score/snapshot migration SQL |
| `python scripts/verify_host_http.py` | Seven artifact types completed; seven detector audits CONFORMS | host-smoke.json; real Uvicorn/HTTP, Semgrep, Hadolint, Trivy and registry calls; SQLite, not PostgreSQL; judge deliberately disabled |
| Diff against CP1 for `scorers.py`, `fusion.py`, `features.py` | Empty | Scorer implementation, fuse() seam and feature schema unchanged |
| `docker info` | Socket permission denied | No image build, Compose startup, live PG/Redis/container restart/CVE-image or Compose schema audit claimed |
| Browser dashboard opening | Approval review rejected: browser permission declined | No alternate browser/automation workaround attempted; visual checks remain unverified |

## Implemented behavior covered by regressions

- Real Semgrep warm-up has a separate cold budget; readiness does not become healthy after a failed warm-up. Warm requests have a bounded scanner timeout. Global dispatch deadlines include queue waiting; cancelled requests retain worker slots until their threads actually finish.
- Memory caches enforce entry limits and TTLs, use bounded Redis pools and retain no transport failures. Shipped ordinary GPL/AGPL policy requires Review; explicit-deny AND/OR semantics and denylist priority are tested.
- SQL transactions store scans, snapshots/routing, normalized executions/findings and fractional scores. Final scans are retrievable, pagination works, SQL files protect content with 0600 mode, and snapshots survive reopening.
- Database callback updates are atomic; overdue pending becomes final error/Review. A late clean callback cannot replace the timeout. Prompt journal jobs/results survive reopening and leases recover abandoned work; provider clients close after failures.
- Typed batch/per-file results validate counts, unique names and byte/work bounds. History reads retain recorded per-file outcomes. PDF responses begin with a valid PDF header. CLI waits for final decisions and rejects invalid/non-finite scores. Corpus mapping preserves supplied labels and server IDs.

## What was not verified

Docker socket access remains denied. The exact host command is `sudo usermod -aG docker cipher`, followed by logging out/in and relaunching Codex so its process receives the new group. This was not run automatically. Then run `docker compose up --build -d` and execute the Compose schema audit as documented in evaluation/phase_a_schema_audit/audit.py.

The local PostgreSQL integration test is skipped without a migrated scratch `TEST_DATABASE_URL`; CI provisions one, but no remote CI pass is claimed yet. Heavy embedding/ScanCode runtime installation and live judge quality/latency have not been validated. Baseline comparison tools have explicit version pins but were not rerun. Direct pins are not complete transitive locks.

Host smoke deliberately disables the judge and observes missing local model/ScanCode availability. Its seven one-off timings are not accuracy, p95, concurrency, cold-start or three-second performance proof. Readiness reports these missing capabilities as degraded and embedding fallback cannot silently Accept. No trained model, SHAP, labeled corpus, public authentication, tenant isolation, TLS termination, build-verified Docker hardening, or automatic history/feature-log retention was added.

## Teammate impact

Protected scorer/fusion/feature files and the detector schema remain unchanged. Public response schema adds typed `per_file`; internal SQL snapshots retain those results. Feature output now has a persistent Compose volume. Multiple callbacks may create intermediate callback-phase rows; choose one with no selected pending agents. Timeout rows retain the existing callback phase and error/uncertainty values. The new corpus runner joins caller-provided labels by request_id; verify log/join completeness before training.

## Publication result

Checkpoint 2 implementation is committed locally. GitHub rejected `git push -u origin codex/checkpoint-2-completion`: the configured Personal Access Token cannot create or update `.github/workflows/ci.yml` without the `workflow` scope. No workflow was removed to bypass this restriction. `gh run list --branch codex/checkpoint-2-completion --limit 5` returned HTTP 401 Bad credentials, so remote CI is unverified. After configuring valid GitHub credentials with workflow permission, run `git push -u origin codex/checkpoint-2-completion`. Checkpoint 1 remains successfully published as `bbd4980`.
