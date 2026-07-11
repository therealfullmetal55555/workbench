"""
Test fixtures.

Two tiers, deliberately:

* **Unit** — pure logic: permissions, entitlements, plan maths, token handling.
  No database, no network, runs in a second. This is what `make test` runs, and
  what CI runs on every push.
* **Database** — the isolation suite. Requires a live Postgres with the
  migrations applied, because the whole point is to prove that *Postgres*
  enforces tenant separation. Mocking the database here would test nothing worth
  testing.

The database fixture connects as the **application role**, never the owner. If
this file ever connects as the owner, every isolation test passes and the
production behaviour is different — which is the most expensive way to be wrong.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

# Tests must never touch a real Stripe account or send real email.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("RATE_LIMIT_BACKEND", "memory")
# The API tests build the real app from settings, so the DSNs have to be present
# in the environment before anything imports `workbench.main`. These point at the
# test database; the application connects as the non-owning role.
os.environ.setdefault(
    "DATABASE_DSN",
    os.getenv(
        "TEST_APP_DSN", "postgresql+asyncpg://workbench:workbench@localhost:5433/workbench_test"
    ),
)
os.environ.setdefault(
    "DATABASE_ADMIN_DSN",
    os.getenv(
        "TEST_ADMIN_DSN",
        "postgresql+asyncpg://workbench_admin:workbench_admin@localhost:5433/workbench_test",
    ),
)
os.environ.setdefault("APP_BASE_URL", "http://localhost:3000")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-to-be-valid-000")
os.environ.setdefault("BILLING_ENABLED", "false")
os.environ.setdefault("LOG_JSON", "false")

from workbench.core.settings import get_settings  # noqa: E402


@pytest.fixture(scope="session")
def settings():
    return get_settings()


@pytest.fixture(scope="session")
def app_dsn() -> str:
    """
    The DSN the isolation suite connects with.

    Points at the application role by default. Override with TEST_APP_DSN when
    running against a compose service.
    """
    return os.getenv(
        "TEST_APP_DSN",
        "postgresql+asyncpg://workbench:workbench@localhost:5433/workbench_test",
    )


@pytest.fixture(scope="session")
def admin_dsn() -> str:
    """The owning role, used only to set up and tear down fixtures."""
    return os.getenv(
        "TEST_ADMIN_DSN",
        "postgresql+asyncpg://workbench_admin:workbench_admin@localhost:5433/workbench_test",
    )


def _postgres_available(dsn: str) -> bool:
    """Synchronous reachability probe so the skip decision happens at collection."""
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(dsn.replace("+asyncpg", ""))
        host, port = parsed.hostname or "localhost", parsed.port or 5432
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(
        os.getenv(
            "TEST_APP_DSN",
            "postgresql+asyncpg://workbench:workbench@localhost:5433/workbench_test",
        )
    ),
    reason="no postgres on TEST_APP_DSN — run `make test-db` with the database up",
)


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db_engine(app_dsn):
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(app_dsn, poolclass=None, echo=False)
    yield engine
    await engine.dispose()


@pytest.fixture
async def admin_engine(admin_dsn):
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(admin_dsn, poolclass=None, echo=False)
    yield engine
    await engine.dispose()


@pytest.fixture
async def admin_session(admin_engine):
    """
    A session as the owning role, for looking at the schema.

    SQLAlchemy 2.0 removed `AsyncEngine.execute` — inspection queries need a
    connection or a session, and this fixture is that, so four tests don't each
    open their own.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(admin_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest.fixture
async def two_orgs(admin_engine):
    """
    Two organisations with one document each, created as the owning role.

    Created via the admin engine because the application role *cannot* write
    rows for an arbitrary org — that's the isolation working, and it makes test
    setup look slightly odd until you remember why.
    """
    from sqlalchemy import text

    acme, beta = uuid.uuid4(), uuid.uuid4()
    doc_a, doc_b = uuid.uuid4(), uuid.uuid4()

    async with admin_engine.begin() as conn:
        for org_id, slug, name in (
            (acme, f"acme-{uuid.uuid4().hex[:8]}", "Acme"),
            (beta, f"beta-{uuid.uuid4().hex[:8]}", "Beta Co"),
        ):
            await conn.execute(
                text("INSERT INTO organizations (id, name, slug) VALUES (:id, :name, :slug)"),
                {"id": org_id, "name": name, "slug": slug},
            )

        for doc_id, org_id, title in (
            (doc_a, acme, "Acme internal"),
            (doc_b, beta, "Beta internal"),
        ):
            await conn.execute(
                text(
                    "INSERT INTO documents (id, org_id, title, body) "
                    "VALUES (:id, :org, :title, 'classified')"
                ),
                {"id": doc_id, "org": org_id, "title": title},
            )

    yield {"acme": acme, "beta": beta, "doc_a": doc_a, "doc_b": doc_b}

    async with admin_engine.begin() as conn:
        await conn.execute(
            text("DELETE FROM organizations WHERE id = ANY(:ids)"),
            {"ids": [acme, beta]},
        )


@pytest.fixture
async def tenant_session_factory(app_dsn):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(app_dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()
