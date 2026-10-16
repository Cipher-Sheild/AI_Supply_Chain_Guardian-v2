# Detector contract 1.0

The authoritative source is `contracts/v1.py`; `scripts/sync_contracts.py` bundles identical copies into all eight independently built services. Run `python3 scripts/sync_contracts.py --check` to detect drift. `contracts/capabilities.json` supplies the shared types, routing table and supported filename/extension sets. API hint validation and detector guards consume those copies. Go, GitLab CI, pyproject.toml and Pipfile have partial specialist coverage; lockfiles remain unscanned.

Every result contains `contract_version`, `agent_name`, `status`, `coverage`, `unresolved`, `decision_floor`, `findings`, optional `evidence` and optional `callback_id`. Pending requires a nonempty callback ID. The called agent must match `agent_name`. Unknown keys fail validation. Confidence is finite in [0,1]; optional finding score is finite in [0,100].

Every finding has category, severity, confidence, location (`original filename:line`), reason, remediation, hard_block, optional score, and an extensible details object. Rich detector models serialize file_path, line_number, detector_id, preview, signals and other extensions into details. Portable fields survive parsing at the Trust Engine. The schema audit checks recursively for missing fields, including findings, details and evidence.

The router chooses expected checks. A check that was not selected is absent from call records and null in feature logs. An expected missing response, stub, error, pending, fail with no findings, incomplete coverage or unresolved result holds at least Review. Numeric confidence cannot cancel a license review. Hard blocks and reject floors force Reject before the scorer is called. Critical Workflow findings and explicit organization license denylist violations carry a reject floor; ordinary license conflicts carry a Review floor. Existing CipherGuard/Secret/Code/Prompt overrides remain authoritative. High or critical severity also prevents Accept.

Requests preserve content, original filename/file_path, type/artifact_type, format, ecosystem, language, ai_tool_source and options. The orchestrator supplies resolved canonical types and manifest/workflow formats before dispatch. Unsupported specialist formats cannot claim full coverage.

Docker engine completion is independent of findings: completed, error_reason, duration_ms, findings. Missing tools, timeouts, registry outages and unverified external registries reduce coverage. A registry 404 can block; an outage cannot be cached as existence. Digest references are parsed but marked unverified until a manifest API verifier exists. Stage aliases and scratch do not trigger external image checks. Mandatory Hadolint/Trivy availability controls Docker readiness. Hardener changes are suggestions, always verification_passed=false: re-linting is not build verification.

## Checkpoint 2 policy decision
Ordinary license conflicts, including GPL/AGPL under no-copyleft, impose a Review minimum. Only an explicit organization `denied_licenses` match carries the license rejection override. Multiple risks can still produce Reject through the unchanged numerical score bands. Go remains partial; no Go rules were added. The version 1.0 detector schema and ML feature schema are unchanged.

## Public API additions (detector contract unchanged)
`POST /analyze/batch` accepts files; ScanResponse adds `per_file` decisions/evidence/coverage for all scans. GET works for final and pending scans; paginated history and PDF audit are new endpoints. Scan storage errors return HTTP 503. Pending expiry becomes a final error that retains Review or stricter policy. Multiple callbacks can produce intermediate callback-phase feature rows; only a row without any selected pending agent is final.

## Final ML extension — 12 October 2026
Detector contract remains 1.0. Public ScanResponse and per-file outcomes add persisted `scoring` metadata (method, model/feature version, optional TreeSHAP baseline/contributions and final policy outcome). Feature observation version is now 2.0: the existing privacy-safe numeric fields gain fixed category-group counts; arbitrary categories/content are excluded. Version-1 logs remain historical; never silently mix them with version-2 model inputs. The trained synthetic pilot is optional, and policy overrides/uncertainty gates remain authoritative.
