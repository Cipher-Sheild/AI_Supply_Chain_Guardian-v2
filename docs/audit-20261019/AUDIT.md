# Repository and security audit - 19 October 2026

This is an engineering audit of the current source checkout, not a certification that the application is flawless. Tests, advisory databases and manual review have finite scope. Weighted enforcement remains the default; ML production promotion remains blocked by the recorded evaluation limitations.

## Review scope

Reviewed the service/API boundaries, authentication and tenant-scoped persistence, callback handling, body/work limits, shared runtime, untrusted artifact parsers, OCI inventory downloads/layers, client HTTP handling, pre-write adapter, frontend development proxy, editor integration, setup/download scripts, Compose and CI configuration. Static analysis covered the Python service/runtime/tooling tree; 305 Python files parsed successfully at the initial syntax pass. Dependency review covered the resolved default runtime/training dependency closure separately from unrelated packages installed on the host. Both npm projects were audited.

No public third-party targets were scanned. Existing demonstration containers, saved history, source datasets, licences and provenance were preserved. Live verification used a separately configured native stack, private state and a disposable PostgreSQL container.

## Confirmed issues and changes

1. **Local browser access boundary:** keyless loopback access previously trusted the peer address without validating Host/Origin. A DNS-rebinding page could therefore reach the local API under an attacker-controlled hostname. Keyless requests now require local hosts/origins and reject cross-site browser requests. Bearer-authenticated deployments retain their own boundary. Regression tests include foreign Host, foreign/null Origin, malformed port and legitimate local frontend requests.
2. **Predictable standalone state:** service defaults placed scan history and callback/feature state under shared `/tmp` names. Default state now uses an owner-only per-user directory and rejects linked/default state targets. Configured launcher/Compose paths remain supported. Feature logging also refuses symlink targets, checks file type/ownership and enforces mode 0600. Tests ensure an unrelated link target remains untouched.
3. **Vulnerable ML dependency pins:** upgraded sentence-transformers 3.0.1 to 5.6.1 and Transformers 4.46.3 to 5.10.4, with compatible Hugging Face Hub/tokenizers and CPU PyTorch 2.14.1. Updated the setup script, prompt container and CI CPU dependency together. Embedding loads explicitly require safetensors, disable remote code and use local-only loading for verified local snapshots. Pinned pip 26.2 and setuptools 83.0.0 for setup/container bootstrap. Advisory sources include [Sentence Transformers' security advisory](https://github.com/advisories/GHSA-jhr6-gm9c-rqjv) and [Transformers' security advisory](https://github.com/advisories/GHSA-xrqw-3rrv-vx5w).
4. **Cold-start model import race:** embedding and local judge warm-up previously ran concurrently and could race through Transformers' lazy imports. Warm-up is now sequential in one background worker. A regression test verifies order; startup failures remain visible through degraded readiness.
5. **Smoke-test log isolation:** the host HTTP checker now writes logs and image jobs into its private temporary directory instead of predictable shared temporary names.
6. **Unbounded event-loop PDF rendering:** audit exports rendered synchronously inside an async API handler. Rendering now uses the bounded worker pool, preserving event-loop responsiveness and returning an explicit 503 when export capacity is exhausted. Regression tests verify worker execution and capacity failure.
7. **Stale developer documentation:** replaced the obsolete engineering overview, added a backend-first developer guide and a rendered PDF, and linked both from README.

## Cleanup and retained structure

Removed the root `package.json`: it was a nonfunctional scanner fixture containing `lodahs` and an old Express version, not an application workspace manifest. Supported npm projects remain under `frontend/` and `integrations/vscode/`; demo package fixtures remain under `demo/fixtures/`.

Removed obsolete `CODE_COMPARISON.md`, `docs/TEAMMATE_MESSAGE.md` and `docs/TRUST_ENGINE_MEMBER_MESSAGE.md`. They contained historical comparisons/handoff instructions, including statements that ML had not been implemented. Dated inventories may still name these files as historical records; Git retains their history.

Stopped versioning the generated VSIX. It remains locally buildable with `npm run package --prefix integrations/vscode`; installation instructions explicitly build it first. Ignored local runtime, authoring intermediates, model caches and node_modules do not enter the push.

Kept regression fixtures, trained model provenance, licence notices, evaluation corpora and dated evidence. Kept generated shared-runtime/contract copies because independent Docker build contexts require them; the canonical sources and sync checks prevent drift. Removing these merely because they are not UI code would damage reproducibility or deployment.

## Verification

- **752 isolated Python regression tests passed**, with one PostgreSQL test skipped in that run; see `unit-suites.json`.
- **The PostgreSQL integration test passed separately** after migrations in a new disposable PostgreSQL 16 container. This makes 753 Python cases passed across separate runs, not one combined invocation.
- **Nine Playwright browser tests passed** against the isolated native backend and private Vite proxy. One intermediate run overlapped a backend restart; its history-export failure passed on retry, followed by a complete nine-test passing run.
- **VS Code extension-host tests passed** for command activation, diagnostic locations, scan-on-save and unavailable-service handling. The output ended with exit code 0. This is not a fresh Copilot UI demonstration.
- Frontend and extension production/TypeScript builds passed; shared contract/runtime drift checks passed; `pip check` passed; Compose configuration validation passed.
- Real MiniLM inference succeeded on the upgraded CPU stack with verified local weights, safetensors-only loading and remote code disabled.
- Fresh native API checks verified unauthenticated history rejection (401), authenticated final Accept, persisted retrieval, PDF output, and safe/unsafe hook allow/deny without creating either target file. An intermediate live stack used Ollama `guardian-judge`; the final stack used the downloaded in-process Qwen judge on PyTorch 2.14.1+cpu. The final safe/unsafe adapter and PDF checks passed again on that stack; see `live-verification.json`.
- The resolved default runtime/training dependency closure contains **116 packages**. Its PyPI advisory scan skipped the vendor `torch==2.14.1+cpu` version, so the equivalent upstream `torch==2.14.1` was checked separately and also reported no known advisories; see `torch-base-dependency-audit.json`. No known advisories were reported for the other audited runtime packages at audit time; both npm projects reported zero known advisories. The closure excludes optional legacy scanners and unrelated host packages. `runtime-dependencies.txt` records installed distribution names; this host exposes the CPU XGBoost module as `xgboost`, while clean setup requests `xgboost-cpu`.
- The current-source credential check found no matches for the inspected configured private credentials; it does not prove a repository history is secret-free.
- The nine-page PDF was rendered and every page inspected for clipping and readability.

The pinned Qwen snapshot download completed, its recorded checksums were generated, and actual local-judge text generation passed. Final prompt-service readiness reported all checks successful. The representative Trust Engine image built from current source and imported the API, bounded PDF helper and private-state helper successfully as its non-root user. This is not a fresh complete Compose deployment or an OS/base-image advisory audit.

## Static-analysis triage

Bandit reported patterns requiring review, including deliberate vulnerable corpus strings, fixed registry URLs, safe parameterised SQL, local pinned model loaders and binding strings used by scanner rules. Its 122 initial findings were not 122 confirmed exploitable vulnerabilities. The concrete shared-temporary-state and temporary-log findings were addressed. No blanket claim that all static warnings are false positives is made; the reviewed operational boundaries and residual limits govern use.

An initial audit of every installed host package also included optional old Semgrep dependencies and unrelated packages (MCP, PyJWT and PyArrow). These are not in the supported default runtime/training dependency closure. The resolved closure was audited independently rather than presenting the host-wide count as application vulnerabilities. Optional external compatibility scanners need their own maintained environments and advisory review.

## Remaining limits

- Detector false positives/false negatives and limited ML generalisation remain documented. Nothing in this audit establishes general accuracy, malicious-input recall or production readiness.
- Registry/advisory reachability can fluctuate and legitimately degrade health or inspection coverage. Do not weaken fail-closed gates to make a demo green.
- The supported Copilot hook has an explicit tool/session boundary; manual edits, arbitrary tools, inline completion and other harnesses are not universally intercepted.
- Public deployment needs ingress TLS, suitable network isolation, backup/restore, monitoring, retention review and workload-specific load/recovery checks.
- Dependency advisories are time-bound. The audit does not cover every OS/base-image package or every future transitive resolution.
- The full installation from an empty OS, native Windows/macOS, all optional providers/scanners, exhaustive container-platform inventories and arbitrary production loads are outside this run.
