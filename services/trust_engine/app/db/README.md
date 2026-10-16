# Operational database

ScanStore in `app/scan_store.py` owns async SQL sessions. Compose applies Alembic migrations and `python -m app.seed` before Trust Engine starts. PostgreSQL is authoritative: snapshots/routing, artifacts/scans, per-agent executions, findings and fractional score commit together. Callback updates use a row lock. Standalone defaults to a durable SQLite file for development, with tables created from models; this is not a migration test. See repository tests and docs/checkpoint-2/VERIFICATION.md for evidence and unrun deployment checks.
