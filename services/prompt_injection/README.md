> Final update: MiniLM is downloaded at a pinned revision into project-local models/minilm by scripts/download_embedding_model.py. Ollama calls request JSON with bounded generation/context and deterministic temperature; judge concurrency defaults to one (maximum two). Live local model checks and timing are in docs/final-validation. Failed/invalid judging remains uncertainty. Exact single-vote typed verdicts use a 512-entry, 10-minute hash-keyed cache; invalid/failed replies are not cached, and multi-vote quorums bypass it. Report cold/warm behavior separately.

# Indirect prompt injection analysis

prompt_injection is one independently deployed HTTP service. Pipeline: `app/extraction.py → app/heuristics.py → app/embeddings.py → app/judge.py`.

Uncertain spans reach a strict typed LLM judge with voting/quorum. Missing embeddings use a partial/unresolved fallback. Pending jobs and resolved deliveries use app/outbox.py, a bounded durable SQLite journal, with leases, restart replay and retry; callback tokens never persist. Live judge quality is not established.

Runtime YAML: `config.yml` is read by this service. See [runtime configuration](../../docs/RUNTIME_CONFIGURATION.md), [versioned contract](../../docs/CONTRACT_V1.md), [status/evidence](../../docs/STATUS.md), and [root deployment guide](../../README.md).

Run standalone from this directory:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m pytest tests -q
```

Do not run all services on the same standalone port. POST `/analyze` returns the shared AgentResult contract for detectors; Trust Engine wraps its fused result with request_id/status/routing/per_file. GET `/health` reports readiness and may return 503 when dependencies are unavailable. Bounded request capacity/body/deadline settings are operational guards, not measured production latency guarantees. Compose runs services as non-root and scopes credentials. Full container integration remains unverified until Docker access is available.
