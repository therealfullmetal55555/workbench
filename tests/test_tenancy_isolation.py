"""
The test this repository exists for.

Every assertion here holds a live Postgres connection open as the *application*
role and checks what the database returns. Not what a service function returns,
not what a repository method filters — what Postgres hands back when asked.

If someone ever removes `ENABLE ROW LEVEL SECURITY`, swaps `SET LOCAL` for `SET`,
or connects the app as the table owner, these fail. That's the point: they're the
tripwire on the one bug that would be a breach rather than an outage.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from workbench.core.db import (
    current_tenant,
    explain_policy,
    set_tenant,
    tenant_session,
    verify_rls_active,
)

from .conftest import requires_postgres

pytestmark = [pytest.mark.database, requires_postgres]


# ---------------------------------------------------------------------------
# The core property
# ---------------------------------------------------------------------------


async def test_unfiltered_select_returns_one_tenant_only(two_orgs, tenant_session_factory):
    """
    The whole design in one assertion.

    A query with no WHERE clause at all comes back with exactly the rows of the
    org bound to the transaction. Application code has to *try* to leak.
    """
    async with tenant_session(tenant_session_factory, two_orgs["acme"]) as session:
        result = await session.execute(text("SELECT id, org_id, title FROM documents"))
        rows = result.all()

    assert len(rows) == 1, f"expected exactly one visible row, got {len(rows)}: {rows}"
    assert rows[0].org_id == two_orgs["acme"]
    assert rows[0].title == "Acme internal"


async def test_the_other_tenant_is_invisible_not_missing(two_orgs, tenant_session_factory):
    """
    Distinguishes 'filtered out' from 'does not exist'.

    Asking for the other org's document by primary key is the strongest form of
    the check: the row exists, the id is correct, and it still doesn't come back.
    """
    async with tenant_session(tenant_session_factory, two_orgs["beta"]) as session:
        exact = await session.execute(
            text("SELECT id FROM documents WHERE id = :id"), {"id": two_orgs["doc_a"]}
        )
        assert exact.first() is None, "tenant B could read tenant A's row by primary key"

        count = await session.execute(text("SELECT count(*) FROM documents"))
        assert count.scalar_one() == 1


async def test_writes_cannot_land_in_another_tenant(two_orgs, tenant_session_factory):
    """
    USING covers reads. WITH CHECK covers writes, and it's the half people forget.

    Without a WITH CHECK, a bug in the insert path plants a row in someone else's
    tenant, and it only surfaces when *they* see it.
    """
    async with tenant_session(tenant_session_factory, two_orgs["acme"]) as session:
        with pytest.raises(Exception) as exc:
            await session.execute(
                text(
                    "INSERT INTO documents (id, org_id, title, body) "
                    "VALUES (:id, :org, 'smuggled', 'x')"
                ),
                {"id": uuid.uuid4(), "org": two_orgs["beta"]},
            )
        assert "row-level security" in str(exc.value).lower() or "policy" in str(exc.value).lower()


async def test_reassigning_org_id_is_blocked(two_orgs, tenant_session_factory):
    """An UPDATE that rewrites org_id is an exfiltration dressed as a bug fix."""
    async with tenant_session(tenant_session_factory, two_orgs["acme"]) as session:
        with pytest.raises(Exception) as exc:
            await session.execute(
                text("UPDATE documents SET org_id = :other"),
                {"other": two_orgs["beta"]},
            )
        message = str(exc.value).lower()
        assert "policy" in message or "row-level security" in message


async def test_delete_only_touches_the_current_tenant(
    two_orgs, admin_engine, tenant_session_factory
):
    async with tenant_session(tenant_session_factory, two_orgs["acme"]) as session:
        await session.execute(text("DELETE FROM documents"))

    async with admin_engine.begin() as conn:
        remaining = await conn.execute(
            text("SELECT org_id FROM documents WHERE id = ANY(:ids)"),
            {"ids": [two_orgs["doc_a"], two_orgs["doc_b"]]},
        )
        survivors = [row.org_id for row in remaining.all()]

    assert survivors == [two_orgs["beta"]], "the other tenant's row was deleted"


# ---------------------------------------------------------------------------
# The mechanism
# ---------------------------------------------------------------------------


async def test_setting_is_scoped_to_the_transaction_and_leaks_nowhere(
    two_orgs, tenant_session_factory
):
    """
    `SET LOCAL` must not survive the commit.

    This is the difference between SET and SET LOCAL, and it is invisible in
    development with a pool of one. Under load, a leaked setting means request B
    runs as tenant A.
    """
    async with tenant_session(tenant_session_factory, two_orgs["acme"]) as session:
        assert await current_tenant(session) == two_orgs["acme"]

    # New transaction, same pooled connection.
    async with tenant_session_factory() as session:
        async with session.begin():
            result = await session.execute(text("SELECT current_setting('app.current_org', true)"))
        assert result.scalar_one_or_none() in (
            None,
            "",
        ), "app.current_org survived the transaction — SET LOCAL was not used"


async def test_tenant_session_refuses_to_guess(app_dsn):
    """
    Falling back to 'no tenant' rather than raising is how RLS ends up disabled
    on one code path that somebody added at 2am.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(app_dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        with pytest.raises(ValueError, match="requires an org_id"):
            async with tenant_session(factory, None):
                pass

        with pytest.raises(ValueError, match="both org_id and bypass"):
            async with tenant_session(factory, uuid.uuid4(), bypass=True):
                pass
    finally:
        await engine.dispose()


async def test_set_tenant_outside_a_transaction_is_refused(two_orgs, tenant_session_factory):
    """
    SET LOCAL outside a transaction applies to exactly one statement and then
    silently stops protecting anything — the worst possible failure: it works in
    a quick manual test and fails on the second query in production.
    """
    async with tenant_session_factory() as session:
        assert not session.in_transaction()
        with pytest.raises(RuntimeError, match="inside a transaction"):
            await set_tenant(session, two_orgs["acme"])


async def test_bypass_requires_saying_so_out_loud(two_orgs, tenant_session_factory):
    async with tenant_session(tenant_session_factory, None, bypass=True) as session:
        result = await session.execute(text("SELECT count(*) FROM documents"))
        # No tenant set, and the role is not the owner: still nothing visible.
        assert result.scalar_one() == 0


# ---------------------------------------------------------------------------
# Deployment safety net
# ---------------------------------------------------------------------------


async def test_every_tenant_table_has_forced_rls(two_orgs, admin_session):
    """
    A table with ENABLE but not FORCE is a table whose policies are bypassed when
    the connecting role owns it.

    That distinction has no failure mode in development, where you're usually the
    owner and usually testing with the owner, and a catastrophic one in
    production.
    """
    unprotected = await verify_rls_active(admin_session)
    assert not unprotected, (
        "these tables expose org_id but do not have FORCE row-level security: " f"{unprotected}"
    )


async def test_policies_exist_on_every_tenant_table(admin_session):
    result = await admin_session.execute(text("""
            SELECT c.relname AS table_name, count(p.polname) AS policies
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_policy p ON p.polrelid = c.oid
             WHERE n.nspname = 'public'
               AND c.relkind = 'r'
               AND EXISTS (
                     SELECT 1 FROM information_schema.columns col
                      WHERE col.table_schema = 'public'
                        AND col.table_name = c.relname
                        AND col.column_name = 'org_id'
                   )
             GROUP BY c.relname
             ORDER BY c.relname
            """))
    rows = result.all()
    assert rows, "no tenant tables found — did the migrations run?"

    # Mirrors the exemptions in scripts/check_rls.py. Two copies, deliberately:
    # this one fails the test suite, that one fails the build, and the reason
    # has to be repeated wherever the decision is written down.
    exempt = {"stripe_events"}

    missing = [row.table_name for row in rows if row.policies == 0 and row.table_name not in exempt]
    assert not missing, f"tenant tables with no policy: {missing}"


async def test_policies_use_the_tenant_setting(admin_session):
    """
    A policy that hardcodes a uuid, or compares against a column that is always
    null, is a policy that compiles and does nothing.
    """
    result = await admin_session.execute(text("""
            SELECT c.relname, pg_get_expr(p.polqual, p.polrelid) AS using_expr
              FROM pg_policy p
              JOIN pg_class c ON c.oid = p.polrelid
             WHERE pg_get_expr(p.polqual, p.polrelid) IS NOT NULL
            """))
    for row in result.all():
        assert (
            "current_setting" in row.using_expr
        ), f"{row.relname} policy does not read a session setting: {row.using_expr}"


async def test_policy_inspection_helper_works(two_orgs, admin_session):
    policies = await explain_policy(admin_session, "documents")
    assert policies, "no policies on documents"
    assert any("current_setting" in (p["using_expression"] or "") for p in policies)
