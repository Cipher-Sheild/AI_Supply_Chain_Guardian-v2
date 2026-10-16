# Checkpoint 1 verification

Tests run independently per service because every service uses the package name `app`. Reproduce with:

```sh
python3 -m venv --system-site-packages /tmp/ptic-checkpoint-venv
/tmp/ptic-checkpoint-venv/bin/pip install fakeredis semgrep==1.172.0 license-expression
/tmp/ptic-checkpoint-venv/bin/python scripts/verify_checkpoint1.py
python3 scripts/sync_contracts.py --check
python3 -m compileall -q services contracts scripts
git diff --check
docker info --format '{{.ServerVersion}}'
```

The final run is 401 passing tests: Trust Engine 191, CipherGuard 16, License Compliance 33, Prompt Injection 41, Code Security 27, Docker Security 38, Secret Detection 29, Workflow 26. After the full-suite run, the Trust Engine callback assertion was updated to expect achieved partial coverage while pending; the complete Trust Engine/CipherGuard suites were rerun with `scripts/verify_checkpoint1.py trust_engine cipherguard` (exit 0). The verifier preserves unaffected service results for focused reruns.

Actual suite summaries and durations are in test-results.json; full final outputs are the eight adjacent `*-tests.txt` files. The verifier imposes a 150-second timeout per service and kills the process group on timeout. Earlier iterations exposed outdated contract assertions, old unsafe judge-quorum expectations and old JS severity expectations; they were updated with explicit regressions. No suite is skipped by the verifier.

The earlier audit's TestClient hangs do not reproduce with unrestricted execution and the installed dependencies. Each suite finishes. This does not prove the exact earlier sandbox/thread interaction; the original cause remains unconfirmed. The first installed Semgrep invocation did exceed the scanner's eight-second bound. The wrapper now disables metrics and version-check network traffic; subsequent real Semgrep fixture tests complete. Startup/cold-load behavior and the global ten-second deadline still need Checkpoint 2 work; no blanket latency guarantee is claimed.

Docker socket access is denied. No Compose builds, container startup, container end-to-end scans, Trivy image CVE scans, live Ollama judgments, live Postgres/migrations, or real Redis durability are verified. Docker scanner failure contracts are tested with controlled subprocess/registry responses. Host binaries are Hadolint 2.15.1 and Trivy 0.74.0. A separate real subprocess smoke scan of `FROM ubuntu:22.04 / USER root / RUN apt-get update` completed successfully: Hadolint found 3 issues in 59.73 ms and Trivy config found 3 in 2934.75 ms (docker-engine-smoke.json). Missing-tool readiness is tested by mocking absence, not by claiming these tools are absent on the host. Registry metadata and judge verdicts are mocked in correctness tests. Secret fixtures contain public/fabricated examples; no .env values were read or logged.

Cross-service contract regressions instantiate each of the seven detectors' real Finding/AgentResult models in separate processes and parse their serialized output with the Trust Engine's authoritative model. This checks every submitted field, portable locations, nested evidence/details, reasons/remediation and rich detector extensions. This is a serialized boundary check, not a running Compose result.

Installed verification environment: Python 3.12.3, Semgrep 1.172.0, fakeredis 2.39.0, Pydantic 2.13.4, FastAPI 0.141.1 and pytest 9.1.1. The temporary venv inherits system/site libraries; this is not a fresh dependency-lock/container validation. Compileall, contract drift verification and git diff --check completed successfully.
