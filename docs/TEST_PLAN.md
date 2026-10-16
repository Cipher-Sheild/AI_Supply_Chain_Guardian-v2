# Test and evaluation plan

Run every service in a separate interpreter working directory because each names its package `app`. Use `VERIFY_OUTPUT_DIR=docs/final-validation .data/venv/bin/python scripts/verify_checkpoint1.py`; logs and JSON preserve results. Explicit PostgreSQL integration requires a migrated scratch TEST_DATABASE_URL. Never point integration fixtures at a valuable production database.

Check contract/runtime drift, corpus hash/group/label provenance, CLI final-state exits, API bounds, PDF structure, SQL restart/row locks, callback races/timeouts, journal leases/retry, scanner outages, partial parsing and subprocess cleanup. Real native Semgrep fixtures cover Python, JS/TS, PHP and Java. Real HTTP smoke covers seven artifact types and seven detector schemas. Native PostgreSQL/Redis/model checks are separate from Compose image checks.

Train only from final, hash-matched corpus responses with independently assigned construction labels. Validate group separation and feature versions. Compare weighted and constrained candidates, select on validation only, reserve grouped test, report false accepts/confusion/MAE/per-type accuracy and safety-gated ablations. Verify native/library SHAP agreement, additivity, monotonicity and that overrides never call the model. Do not infer real-world detector accuracy from unit tests or synthetic author-controlled labels.

Measure cold/warm initial latency separately from asynchronous time-to-final using evaluation/phase_b_latency tools. Preserve failures/incomplete observations in reports. Live judging on CPU can be slow; no three-second guarantee is made. The prior historical benchmark numbers are not new results.

Manual remaining checks: dashboard browser interaction, VS Code command/diagnostics/cancellation, complete Docker startup/resource/permission behavior, live container restart delivery, hardening image builds and independently reviewed external held-out artifacts. The browser denial must not be bypassed with alternative automation.
