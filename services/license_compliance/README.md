# SPDX license identification and policy checks

license_compliance is one independently deployed HTTP service. Pipeline: `app/extraction.py → app/license_lookup.py → app/policy.py → app/conflict_engine.py`.

Registry metadata and optional ScanCode fallback preserve SPDX expression structure. AND/OR/WITH/unknown nodes remain explicit. Ordinary conflicts hold Review; only an explicit organization denied_licenses match can hard-block. Denylist defaults empty. One-level transitive checks are best effort.

Runtime YAML: `config.yml` is read by this service. See [runtime configuration](../../docs/RUNTIME_CONFIGURATION.md), [versioned contract](../../docs/CONTRACT_V1.md), [status/evidence](../../docs/STATUS.md), and [root deployment guide](../../README.md).

Run standalone from this directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m pytest tests -q
```

Do not run all services on the same standalone port. POST `/analyze` returns the shared AgentResult contract for detectors; Trust Engine wraps its fused result with request_id/status/routing/per_file. GET `/health` reports readiness and may return 503 when dependencies are unavailable. Bounded request capacity/body/deadline settings are operational guards, not measured production latency guarantees. Compose runs services as non-root and scopes credentials. Full container integration remains unverified until Docker access is available.
