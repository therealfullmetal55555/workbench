"""
Alembic environment.

Two things here are not boilerplate:

1. The DSN comes from settings, not from alembic.ini. A migration that runs
   against the wrong database is not a small mistake.
2. Migrations run as the *admin* role, because creating policies and grants
   requires owning the tables. The application role cannot and should not be
   able to run them — that separation is what makes RLS trustworthy.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from workbench.core.models import Base  # noqa: E402
from workbench.core.settings import get_settings  # noqa: E402

# Import every model module so autogenerate sees the full metadata. A model that
# isn't imported here is a table Alembic will happily try to drop.
import workbench.auth.models  # noqa: F401,E402
import workbench.billing.models  # noqa: F401,E402
import workbench.audit.models  # noqa: F401,E402
import workbench.tenancy.models  # noqa: F401,E402
import workbench.data.models  # noqa: F401,E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    settings = get_settings()
    # Migrations must run as the owner, never as the application role.
    return str(settings.postgres_admin_dsn)


def include_object(obj, name, type_, reflected, compare_to):  # noqa: ANN001
    """Keep Alembic out of other people's business."""
    if type_ == "table" and name in {"spatial_ref_sys", "alembic_version"}:
        return False
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        include_object=include_object,
        # We hand-write RLS; autogenerate would try to drop the policies it
        # doesn't model, which is a data-exposure bug rather than a diff.
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
