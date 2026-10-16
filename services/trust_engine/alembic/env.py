"""Migrations read DATABASE_URL; ENV_FILE is an optional explicit dotenv path."""
import os
import sys
from pathlib import Path
from alembic import context
from sqlalchemy import create_engine, pool
from dotenv import load_dotenv
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.getenv("ENV_FILE"):
    load_dotenv(os.environ["ENV_FILE"], override=False)
from app.db.models import Base
url = os.getenv("DATABASE_URL", "postgresql+asyncpg://guardian:guardian@postgres:5432/guardian")
url = url.replace("postgresql+asyncpg", "postgresql+psycopg2").replace("sqlite+aiosqlite", "sqlite")
if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True, dialect_opts={"paramstyle":"named"})
    with context.begin_transaction(): context.run_migrations()
else:
    engine = create_engine(url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction(): context.run_migrations()
