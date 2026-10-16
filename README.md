# AI Supply Chain Guardian

A local pre-acceptance artifact review platform with seven detector services, a Trust Engine, persisted history, CLI/pre-commit, dashboard/PDF and an explicit VS Code command. It supports the deterministic weighted baseline and an optional constrained XGBoost synthetic-pilot scorer with exact TreeSHAP. Hard overrides and uncertainty gates remain authoritative.

## Documentation

- [Complete project description, every agent, design and scope](docs/FINAL_PROJECT_DOCUMENTATION.md)
- [User manual](docs/USER_MANUAL.md), [requirements](docs/SRS.md), [system design](docs/SDD.md), [test plan](docs/TEST_PLAN.md)
- [Dataset and labeling guide](docs/DATA_LABELING_GUIDE.md), [training/evaluation](evaluation/trust_model/README.md)
- [Current status](docs/STATUS.md), [final verification](docs/final-validation/VERIFICATION.md)
- [Detector contract](docs/CONTRACT_V1.md), [executable runtime settings](docs/RUNTIME_CONFIGURATION.md)
- [Historical project reference](docs/reference/PROJECT_DOCUMENTATION_2026-10-11.md)

## Local start

Python 3.12, Node 22+, npm, Hadolint 2.15.1 and Trivy 0.74.0 are required; setup copies matching host tools or downloads/checks release assets into .tools/bin. The setup installs CPU Torch/ML/ScanCode/Semgrep dependencies and pinned embedding weights inside the project. Start Ollama and obtain llama3.2:latest, then create the bounded judge alias.

```bash
python3 scripts/setup_local.py
ollama create guardian-judge -f services/prompt_injection/models/OllamaModelfile
.data/venv/bin/python scripts/run_local.py --python "$PWD/.data/venv/bin/python" --dashboard
```

Dashboard: http://127.0.0.1:3000. Trust Engine: http://127.0.0.1:18108. Ctrl-C stops owned services. Default SQL is local SQLite; use an explicitly migrated PostgreSQL URL and running Redis when desired. Optional model mode is `--scorer ml`. `--state-dir` isolates storage/journals when running distinct stacks. Do not reuse a journal across unrelated callback endpoints.

Compose uses internal detector ports, PostgreSQL migration/seed dependencies and a same-origin dashboard proxy. Configure a private `.env` using `.env.example`, then `docker compose up --build -d` once Docker access is available. Container execution is not verified on this host.

## Current evidence and limits

See the final verification report for exact service/script counts and commands. The 360-artifact pilot has independent-by-construction labels, but no independent human reviewer: 180/90/90 grouped train/validation/test. On 90 grouped synthetic test rows, weighted and XGBoost both reach 77.8% decision accuracy; XGBoost reduces false accepts from 5 to 0 while moving 10 clean rows to Review. MAE improves from 19.58 to 14.83 against engineering score anchors. This is not real-world accuracy or probability calibration, and the model is not promoted to the default. Native/library TreeSHAP agree; tested observed-feature monotonicity holds.

Go/GitLab/full dependency graph support remains partial/out of scope. Hardening outputs are unverified suggestions. Public user authentication/TLS/tenant isolation, automatic retention and universal AI-assistant Accept-button interception are not delivered. Browser/editor interaction and full Docker deployment still need manual proof. Preserve private .env/.data and protect submitted-content storage; returned credential masking is output hygiene, not proof that every secret format can be detected.

No changes from this final run are pushed to the old remote. The user will provide a new repository for publication.
