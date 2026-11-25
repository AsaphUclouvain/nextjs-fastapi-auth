import os

from alembic import context
from sqlalchemy import create_engine

from app import models  # noqa: F401  (registers tables)
from app.db import Base

config = context.config
url = config.attributes.get("url") or os.environ.get("DATABASE_URL", "sqlite:///./app.db")


def run_migrations_online() -> None:
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=url.startswith("sqlite"))
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    run_migrations_online()
