"""
Database plumbing, and the tenant session.

The important part of this file is `set_tenant()`. Everything else is ordinary
SQLAlchemy ceremony.

How isolation works here:

    1. A request resolves its organisation (from a path param, header, or JWT).
    2. `tenant_session()` opens a transaction and runs
           SET LOCAL app.current_org = '<uuid>'
       `SET LOCAL` is scoped to the transaction — it cannot leak to the next
       request that borrows the pooled connection. `SET` would leak, and that bug
       is invisible until two tenants collide under load.
    3. Every policy in the database compares `org_id` against that setting.
    4. The transaction commits or rolls back, and the setting evaporates.

Consequence: application code that forgets its tenant filter reads nothing. It
does not read someone else's rows. That's the whole point.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any, TypeVar

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from workbench.core.settings import Settings, get_settings

log = logging.getLogger(__name__)

T = TypeVar("T")

# The Postgres GUCs the policies read. Named `app.*` so they can't collide with a
# built-in setting.
#
# Two of these are ordinary request context:
TENANT_SETTING = "app.current_org"
ACTOR_SETTING = "app.current_user"
# ...and the rest are *credentials*, in the literal sense: a request that writes
# one is presenting something it was given and asking to be recognised by it.
# They exist so the application never needs a SECURITY DEFINER function to see
# around row-level security. See `api/context.py` for the argument, and
# migrations/0001 for what happened when this was done the other way.
#
#   current_login_email       — the address a login attempt named
#   current_credential        — a hashed token, or an API key prefix
#   current_billing_customer  — a Stripe customer id from a signed webhook
#   current_billing_subscription — a Stripe subscription id from the same
#
# Each one only ever widens visibility to the single row whose key it carries,
# and each is written by code that has already authenticated whatever it is
# presenting. A GUC is per transaction, so a connection returning to the pool
# carries none of them.
CREDENTIAL_SETTING = "app.current_credential"
LOGIN_EMAIL_SETTING = "app.current_login_email"
BILLING_CUSTOMER_SETTING = "app.current_billing_customer"
BILLING_SUBSCRIPTION_SETTING = "app.current_billing_subscription"
# Marks a session as belonging to a verified staff member, which is the one
# thing in this system that reads across customers. It is a GUC rather than a
# role because RLS cannot see which user a connection belongs to, and the
# alternative — a BYPASSRLS role for the console — hands every console request
# the ability to read every table. This way each table opts in individually, and
# the list of tables staff can see is a list you can read.
STAFF_SETTING = "app.staff"
# Set only by background jobs, and read by a handful of narrow policies that
# allow maintenance work with no tenant: revoking expired invitations, pruning
# dead refresh chains, closing a usage period. Without these, a job that runs
# outside a tenant deletes nothing at all — and reports success, because RLS
# filters rows rather than raising. That silence is why these policies exist
# instead of a job that quietly does nothing.
MAINTENANCE_SETTING = "app.maintenance"
# Marks a request as coming from staff impersonation. Policies don't change, but
# triggers record it and write paths can refuse.
IMPERSONATED_SETTING = "app.impersonated"


def create_engine(settings: Settings | None = None, **overrides: Any) -> AsyncEngine:
    settings = settings or get_settings()
    options: dict[str, Any] = {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_recycle": settings.db_pool_recycle_seconds,
        # Recycle before the pooler does, so we never hand out a socket that a
        # pgbouncer or a NAT has already closed.
        "pool_pre_ping": True,
        # No `echo`. SQLAlchemy's echo installs its *own* handler on the
        # `sqlalchemy.engine.Engine` logger, so in development every statement is
        # printed twice — once plain by SQLAlchemy, once structured by the root
        # handler `configure_logging` installed — and the duplication is
        # invisible in review, because it only appears when the app runs.
        # `configure_logging` already raises that logger to INFO in development,
        # which is the same information through one formatter.
        "echo": False,
    }
    options.update(overrides)
    return create_async_engine(str(settings.postgres_dsn), **options)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,  # objects stay usable after commit; FastAPI serialises after
        autoflush=False,
    )


# Kept as a function rather than a global `after_begin` listener on purpose.
#
# A listener attached to AsyncSession would fire for sessions opened by Alembic,
# by the admin console's bypass sessions, and by tests — and a timeout silently
# applied to a long migration is a confusing failure five minutes later. Setting
# it explicitly in `begin_scoped_transaction()` means the timeout exists exactly
# where requests exist, and you can read where it comes from.
async def _apply_statement_timeout(session: AsyncSession) -> None:
    """
    Cap how long any single statement may run.

    Without this, one unindexed query on a large tenant's audit log holds a
    connection for minutes, the pool drains, and a single slow endpoint becomes a
    site-wide outage. The timeout turns that into one failed request.
    """
    connection = await session.connection()
    if connection.dialect.name != "postgresql":
        return
    timeout = get_settings().db_statement_timeout_ms
    # Interpolated, not parameterised: Postgres does not accept a bind parameter
    # in SET. The value is an int from validated settings, never user input.
    await session.execute(text(f"SET LOCAL statement_timeout = {int(timeout)}"))


# ---------------------------------------------------------------------------
# Tenant context
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def tenant_session(
    factory: async_sessionmaker[AsyncSession],
    org_id: uuid.UUID | str | None,
    *,
    actor_id: uuid.UUID | str | None = None,
    impersonated: bool = False,
    bypass: bool = False,
) -> AsyncIterator[AsyncSession]:
    """
    A session scoped to one tenant.

    `org_id=None` is only legal with `bypass=True` and is for the paths that
    genuinely have no tenant: signup, login, Stripe webhooks resolving a customer,
    the staff admin console. Those call sites have to say so out loud, which is
    what stops `bypass=True` from quietly spreading.
    """
    if org_id is None and not bypass:
        raise ValueError(
            "tenant_session requires an org_id; pass bypass=True deliberately if this "
            "code path really has no tenant"
        )
    if org_id is not None and bypass:
        raise ValueError("tenant_session got both org_id and bypass=True — pick one")

    async with factory() as session, session.begin():
        await _apply_statement_timeout(session)
        if org_id is not None:
            await set_tenant(session, org_id, actor_id=actor_id, impersonated=impersonated)
        elif actor_id is not None:
            # An actor with no tenant. This is the signup path, login, and
            # `POST /orgs` — and it is not optional: three policies key off
            # `app.current_user` rather than off a tenant. `organizations`
            # only allows an insert by the user who is creating it,
            # `users_self_update` only allows a user to edit themselves, and
            # the audit policy only allows a tenant-less event about
            # yourself. Without this, creating an org fails with a
            # row-level security violation that gives no hint which setting
            # was missing.
            await set_actor(session, actor_id)
        yield session


async def commit_evidence(session: AsyncSession) -> None:
    """
    Commit the writes that have to outlive the request that is about to fail.

    Most writes belong to the request. If the handler raises, the transaction is
    rolled back and, correctly, nothing happened.

    A few writes are not like that. A failed sign-in, a detected token replay, a
    revoked token family — these are *about* the failure, and the failure is
    exactly when they matter. Rolled back along with everything else, the lockout
    counter never reaches its threshold, the reuse detector revokes a family that
    stays alive, and the table recording every attack stays empty. None of it is
    visible from the outside: the responses are identical either way, so a test
    that asserts on status codes passes while the protection does nothing. It was
    found here by counting rows in `login_attempts` after three failed sign-ins
    and finding zero.

    Call it immediately before raising, never anywhere else. It is a separate
    call rather than a flag on the session on purpose: the places that need it
    are few, and each one should be read by whoever changes it next.
    """
    await session.commit()


async def set_tenant(
    session: AsyncSession,
    org_id: uuid.UUID | str,
    *,
    actor_id: uuid.UUID | str | None = None,
    impersonated: bool = False,
) -> None:
    """Bind the current transaction to a tenant. Must run inside a transaction."""
    if not session.in_transaction():
        raise RuntimeError(
            "set_tenant must be called inside a transaction — SET LOCAL outside one "
            "applies for exactly one statement and then silently stops protecting you"
        )

    # set_config(..., is_local => true) is the parameterised form of SET LOCAL.
    # Interpolating the uuid here instead would be an injection point that RLS
    # cannot save you from, because it runs before the policies do.
    await session.execute(
        text("SELECT set_config(:key, :value, true)"),
        {"key": TENANT_SETTING, "value": str(org_id)},
    )
    if actor_id is not None:
        await session.execute(
            text("SELECT set_config(:key, :value, true)"),
            {"key": ACTOR_SETTING, "value": str(actor_id)},
        )
    if impersonated:
        await session.execute(
            text("SELECT set_config(:key, :value, true)"),
            {"key": IMPERSONATED_SETTING, "value": "on"},
        )


async def set_actor(session: AsyncSession, actor_id: uuid.UUID | str) -> None:
    """
    Bind `app.current_user` without binding a tenant.

    Separate from `set_tenant` because the two are genuinely independent: signup
    has an actor and no org, and the staff console has neither. Kept tiny and
    parameterised so nobody is tempted to interpolate an id into SQL to save a
    function call.
    """
    if not session.in_transaction():
        raise RuntimeError("set_actor must be called inside a transaction")
    await session.execute(
        text("SELECT set_config(:key, :value, true)"),
        {"key": ACTOR_SETTING, "value": str(actor_id)},
    )


async def set_credential(session: AsyncSession, key: str, value: str) -> None:
    """
    Present something to the policies without opening a tenant.

    Used for the four credential settings above: a login attempt naming an email,
    a refresh token being exchanged, an API key prefix, a Stripe customer id
    arriving on a signature-verified webhook. Every one of these is a value the
    caller already holds; none of them is a tenant, and none of them can be used
    to read a row that the value doesn't name.

    Parameterised. Interpolating here would be an injection point that runs
    *before* the policies do, which is the one place row-level security cannot
    save you from.
    """
    if not session.in_transaction():
        raise RuntimeError("set_credential must be called inside a transaction")
    await session.execute(
        text("SELECT set_config(:key, :value, true)"), {"key": key, "value": str(value)}
    )


async def current_tenant(session: AsyncSession) -> uuid.UUID | None:
    """Read back the tenant bound to this transaction. Used by tests and the admin console."""
    result = await session.execute(text(f"SELECT current_setting('{TENANT_SETTING}', true)"))
    raw = result.scalar_one_or_none()
    return uuid.UUID(raw) if raw else None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


async def ping(session: AsyncSession) -> bool:
    try:
        await session.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 — health checks must not raise
        log.exception("database health check failed")
        return False


# Tables that carry `org_id` and are deliberately not protected by a tenant
# policy. Keep this list almost empty: every entry is a table whose rows any
# code path holding a database connection can read across customers.
#
# `scripts/check_rls.py` holds its own copy of this, on purpose. The script runs
# in CI and refuses to merge a migration that adds an unprotected table; this one
# runs at startup and refuses to serve traffic. Two independent checks failing
# for the same reason is not duplication, it's a decision that has to be
# restated wherever it matters.
RLS_EXEMPT: dict[str, str] = {
    "stripe_events": "idempotency ledger — written before the org is known",
}


async def verify_rls_active(session: AsyncSession, exempt: set[str] | None = None) -> list[str]:
    """
    Return tenant tables that would NOT be protected.

    Called at startup. A table that is missing `ENABLE ROW LEVEL SECURITY`, or
    that is missing `FORCE`, is a table whose policies are silently ignored when
    the connecting role owns it. That's a two-line mistake with a very bad blast
    radius, so it's checked rather than assumed.
    """
    exempt = set(RLS_EXEMPT) if exempt is None else exempt
    result = await session.execute(text("""
            SELECT c.relname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public'
               AND c.relkind = 'r'
               AND EXISTS (
                     SELECT 1 FROM information_schema.columns col
                      WHERE col.table_schema = 'public'
                        AND col.table_name = c.relname
                        AND col.column_name = 'org_id'
                   )
               AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
             ORDER BY c.relname
            """))
    return [row[0] for row in result.all() if row[0] not in exempt]


async def explain_policy(session: AsyncSession, table: str) -> list[dict[str, Any]]:
    """Dump the policies on one table.

    Handy in the specific situation where a query returns nothing and you are
    sure it should have returned something.
    """
    result = await session.execute(
        text("""
            SELECT polname AS name,
                   polcmd   AS command,
                   pg_get_expr(polqual, polrelid)       AS using_expression,
                   pg_get_expr(polwithcheck, polrelid)  AS check_expression
              FROM pg_policy
             WHERE polrelid = to_regclass(:table)
            """),
        {"table": table},
    )
    return [dict(row._mapping) for row in result.all()]
