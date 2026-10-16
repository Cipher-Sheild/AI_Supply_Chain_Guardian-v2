# Trust Engine

The public integration API routes relevant detectors, applies authoritative hard overrides/uncertainty gates, persists every scan and exposes history, per-file outcomes, audit PDFs and authenticated callbacks. Numerical scoring defaults to the weighted baseline. `TRUST_SCORER=ml` enables the bundled synthetic-pilot XGBoost candidate; missing/corrupt models visibly fall back to weighted scoring. Exact TreeSHAP explanations are additive public `scoring` metadata, persisted with scans.

Read [complete current documentation](../../docs/FINAL_PROJECT_DOCUMENTATION.md), [runtime configuration](../../docs/RUNTIME_CONFIGURATION.md), and [training/data notes](../../evaluation/trust_model/README.md). Detector contract remains 1.0; privacy-safe feature observations are 2.0, adding fixed numeric category groups. Hard overrides bypass model invocation and all missing/pending/error/coverage floors remain external to ML.

Compose uses PostgreSQL with Alembic migration/seed dependencies; standalone defaults to SQLite. Only this service writes scan history. Callback updates are atomic and overdue pending becomes final uncertainty; historical outcomes are not recalculated on GET. Submitted content in snapshots requires protected retention/backups. Public multi-tenant auth/TLS is not implemented.
