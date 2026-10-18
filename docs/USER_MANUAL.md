# Local user manual

1. Run `python3 scripts/setup_local.py` from the repository. Python 3.12, Node 22+, npm, Hadolint 2.15.1 and Trivy 0.74.0 are required; setup copies matching host tools or downloads/checks release assets into .tools/bin. The setup creates `.data/venv`, installs CPU model/training dependencies, downloads pinned MiniLM weights and obtains native tools in .tools/bin. The launcher restricts its state directory to the owner. A local Ollama server/model is required for semantic judging; this host has llama3.2:latest and a bounded guardian-judge alias.
2. Launch `.data/venv/bin/python scripts/run_local.py --python "$PWD/.data/venv/bin/python" --dashboard`. Default Trust Engine is http://127.0.0.1:18108 and dashboard http://127.0.0.1:3000. Logs and local SQL/journal/feature observations live in private `.data`. Ctrl-C stops the owned services. Do not run a second stack on those ports.
3. Paste content and a meaningful filename, or select bounded files. Read findings, coverage and uncertainty—not just the number. A provisional result is not approval; wait for final status. History and PDF export retain recorded outcomes.
4. CLI: `.data/venv/bin/python scripts/guardian_cli.py --url http://127.0.0.1:18108 path/to/artifact.py`. Exit 0 requires final Accept and threshold; 2 is Review/threshold; 3 is Reject; 4 is unavailable/invalid/incomplete. The hook definition is `.pre-commit-hooks.yaml`; pass the local URL via GUARDIAN_URL when using native ports. Intentionally vulnerable test/corpus fixtures should be excluded from your own repository's commit gate.
5. Optional learned mode: restart the launcher with `--scorer ml`. The synthetic pilot's model identity/scope and TreeSHAP contributions are displayed. The model does not bypass overrides or uncertainty. Default weighted mode remains available. Missing/corrupt/incompatible model artifacts cause an explicit weighted fallback.
6. VS Code: install `integrations/vscode/guardian.vsix`, set guardian.serverUrl to http://127.0.0.1:18108, and run **Guardian: Scan Active Artifact**. It scans the unsaved active buffer only when requested; updates diagnostics after finalization and invalidates results when the document changes. This is not an automatic provider Accept-button hook. Editor interaction still needs manual verification.
7. PostgreSQL: migrate a dedicated local database using the Trust Engine Alembic config, run `python -m app.seed` from that service with DATABASE_URL, then pass that URL through `--database-url`. Use `--redis-url` for a running local Redis. A configured PostgreSQL outage does not silently fall back to SQLite.
8. Compose: set a private `.env` from `.env.example`, obtain Docker daemon access and run `docker compose up --build -d`. Trust Engine uses 8000 and dashboard 3000. Container checks remain unverified in this environment. Never commit `.env` or `.data`.

Common failures: 503 health means a required tool/model/registry/database is unavailable; inspect individual check fields/private logs. Scan timeouts and unsupported coverage require review. Callback auth must match between prompt and Trust Engine; the native launcher sets a fresh shared value without printing it. PDF/model contributions cannot turn incomplete evidence into proof of safety.

### Local demonstration dashboard

For the loopback-only demonstration, the Vite dashboard can read a private client
configuration through `GUARDIAN_DASHBOARD_CLIENT_CONFIG=/absolute/path/client.env`,
with `TRUST_ENGINE_URL=http://127.0.0.1:18808`. Start it using
`npm run dev -- --host 127.0.0.1 --port 3000 --strictPort` from `frontend/`.
The file must be a regular non-symlink file, mode 600, under 64 KiB, with one
unquoted `GUARDIAN_API_KEY` entry. The key stays on the server; this mode rejects
foreign-origin proxy requests and must not be exposed to a network. Other
configurations retain explicit client-key access in the dashboard.

History refreshes every five seconds on page one while the tab is visible.
Click a row to view evidence, or use its Download PDF button without opening it.
Reports download as `guardian-<request_id>.pdf` to the browser's configured download
directory. A confirmation shows the filename. PDF generation is on demand, not an
automatic artifact written by the VS Code hook. A provisional report can change;
check the scan's final/provisional label before sharing.
