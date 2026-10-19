# AI Supply Chain Guardian: current engineering overview

Updated 19 October 2026. Use [the developer guide](DEVELOPER_GUIDE.md) for the supported clone-to-run sequence and [the audit record](audit-20261019/AUDIT.md) for verification scope and remaining limits. Historical checkpoint reports describe their dated revisions.

## Delivered system

Seven artifact-specific detector services feed the Trust Engine. Authenticated web, CLI and VS Code clients receive Accept / Review / Reject decisions, a numerical trust score, findings, coverage and explanations. A separately configured Local Copilot PreToolUse adapter gates supported file-tool proposals. It is not universal interception of all assistant actions.

The scanners review source code, secrets, package metadata, Docker/Compose and supported image inventories, GitHub/GitLab workflows, supplied licence text/dependency licence metadata, and prompt-injection signals. The canonical routing matrix is `contracts/capabilities.json`. Only applicable detectors run; missing checks and unresolved evidence cannot count as successful inspection.

## Runtime and data ownership

Eight FastAPI processes or containers implement seven scanners plus the Trust Engine. LangGraph coordinates bounded dispatch and fusion. These are specialist scanner services; they do not negotiate as independent reasoning agents.

The Trust Engine owns SQL scan history. Native development uses SQLite; Compose uses migrated PostgreSQL. Scan snapshots retain submitted artifacts, detector evidence, per-file outcomes and scoring metadata. Protect private runtime storage. Redis provides caches; durable callback/image jobs use bounded SQLite journals. Default standalone state uses the current user's private `~/.local/state/guardian` directory; the launcher and Compose configure explicit private storage paths.

## Policy, scoring and explanations

Deterministic weighted scoring is the default. Hard rejection overrides, severity floors, coverage and unresolved/error gates are authoritative. The optional 98-feature XGBoost regressor and exact TreeSHAP explain the model score before policy gates. The v4 candidate is retained under `evaluation/trust_model/v4-clean-patterns`; it is not automatically selected by the ordinary native or Compose launcher. Historical service models and evaluation candidates are versioned separately.

Weighted enforcement and ML comparisons must use the same detector observations when making paired claims. Synthetic development results and selected Copilot fixtures do not establish general detection accuracy. See [the final readiness audit](../evaluation/trust_model/readiness-audit-20261019/README.md) for the remaining model and detector limitations.

## Interfaces and security boundaries

The API supplies health, single/batch analysis, authenticated internal callbacks, tenant-scoped history and audit PDF export. Client API credentials are separate from callback/provider credentials. Production startup requires configured strong credentials. Keyless local access is restricted to loopback peers and local browser hosts/origins. TLS and public ingress remain deployment responsibilities.

The CLI discovers supported files and waits for final outcomes. The editor command scans the active buffer; scan-on-save is distinct from pre-write gating. Supported Copilot file proposals require final Accept; Review, Reject and inspection failure deny a supported write. Manual edits, arbitrary tools and other harnesses remain outside that boundary.

## Source structure and maintenance

- `services/`: independent service build contexts and service-specific tests.
- `runtime/`: canonical shared operational modules; generated service copies are necessary for independent containers. Verify with `scripts/sync_runtime.py --check`.
- `contracts/`: shared schemas/capabilities; verify with `scripts/sync_contracts.py --check`.
- `frontend/`, `integrations/vscode/`: client interfaces.
- `scripts/`: setup, launch, clients, verification and training tooling.
- `evaluation/`: datasets, labels, model provenance, recorded observations and limitations. These are retained research evidence, not runtime clutter.
- `docs/`: design references, reports, current guide and dated audits.
- `.data/`, `tmp/`, `node_modules/`, generated VSIX and frontend bundles: ignored local artifacts.

## Verification and remaining work

Use the audit's exact results rather than assuming every prior report was rerun. Unit suites, PostgreSQL lifecycle checks, interface builds, actual model inference, browser interaction and complete Compose deployment are separate verification scopes. A package advisory scan is time-bound and cannot prove absence of vulnerabilities.

Broader independent security datasets, detector calibration, malicious-input recall across all domains, deployment recovery/load/retention checks and public-service hardening remain necessary before a production assurance claim. Third-party licence notices and upstream provenance must remain with retained examples.
