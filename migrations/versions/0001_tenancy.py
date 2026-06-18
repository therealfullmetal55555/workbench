"""tenancy: organizations, memberships, invitations, and the RLS that protects them

Revision ID: 0001_tenancy
Revises:
Create Date: 2026-09-29

This migration is the reason the repo exists, so it's commented more heavily
than the others. Read the RLS section before changing anything in it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_tenancy"
down_revision = None
branch_labels = None
depends_on = None

# Tables created *by this migration* that carry `org_id`. The helper below takes
# this list literally, so a table added to the models without being added here
# ends up unprotected — which is why scripts/check_rls.py runs in CI and reads
# the catalogue rather than trusting this list.
TENANT_TABLES = ("memberships", "invitations", "documents")


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")  # gen_random_uuid, digest

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------
    # Two roles, and the separation is load-bearing.
    #
    #   workbench_admin — owns the tables, runs migrations. Row-level security
    #     is bypassed for a table's owner unless FORCE is set (we set it, but
    #     the owner is still the wrong role to serve traffic with: a single
    #     `ALTER TABLE ... DISABLE` in a future migration silently removes
    #     protection from production).
    #
    #   workbench — the application. Owns nothing, so every policy applies
    #     unconditionally, with no FORCE to forget.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workbench') THEN
                CREATE ROLE workbench LOGIN PASSWORD 'workbench' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'workbench_admin') THEN
                CREATE ROLE workbench_admin LOGIN PASSWORD 'workbench_admin' NOSUPERUSER NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
        """
    )

    # ------------------------------------------------------------------
    # organizations
    # ------------------------------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("onboarding_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("billing_customer_id", sa.String(64), nullable=True, index=True),
        sa.Column("overrides", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("settings", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'", name="ck_organizations_slug_format"),
    )
    op.create_index("ix_organizations_active_slug", "organizations", ["is_active", "slug"])

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("name", sa.String(200), nullable=False, server_default=""),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_staff", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("staff_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("totp_secret", sa.String(255), nullable=True),
        sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # Case-insensitive uniqueness enforced by the database rather than by a
    # normalisation function that someone will forget to call.
    op.execute("CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email))")

    # ------------------------------------------------------------------
    # memberships
    # ------------------------------------------------------------------
    role_enum = postgresql.ENUM(
        "owner", "admin", "member", "viewer", name="membership_role", create_type=False
    )
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE membership_role AS ENUM ('owner','admin','member','viewer'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
    )

    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("role", role_enum, nullable=False, server_default="member"),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("invited_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        # Invite twice and the second one fails, even under concurrency.
        sa.UniqueConstraint("user_id", "org_id", name="uq_memberships_user_id_org_id"),
    )
    op.create_index("ix_memberships_org_role", "memberships", ["org_id", "role"])

    # ------------------------------------------------------------------
    # invitations
    # ------------------------------------------------------------------
    invitation_role = postgresql.ENUM(
        "owner", "admin", "member", "viewer", name="invitation_role", create_type=False
    )
    op.execute(
        "DO $$ BEGIN "
        "CREATE TYPE invitation_role AS ENUM ('owner','admin','member','viewer'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
    )

    op.create_table(
        "invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("email", sa.String(320), nullable=False, index=True),
        sa.Column("role", invitation_role, nullable=False, server_default="member"),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invited_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("send_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # One *live* invitation per email per org. A partial index, because accepted
    # and revoked rows are history and history should accumulate.
    op.execute(
        """
        CREATE UNIQUE INDEX uq_invitations_pending_email
            ON invitations (org_id, email)
         WHERE accepted_at IS NULL AND revoked_at IS NULL
        """
    )

    # ------------------------------------------------------------------
    # documents — the sample tenant-owned table
    # ------------------------------------------------------------------
    # A deliberately boring table. It exists so the isolation suite has something
    # to prove a point with, and so the pattern for a tenant table is copyable.
    op.create_table(
        "documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("body", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_documents_org_created", "documents", ["org_id", sa.text("created_at DESC")])

    # Documents carries two indexes the models declare; a tenant table with no
    # index on org_id makes every tenant-scoped query a sequential scan, which is
    # fine in dev and not fine at a thousand customers.
    op.create_index("ix_documents_org_id", "documents", ["org_id"])
    op.create_index("ix_documents_deleted_at", "documents", ["deleted_at"])

    # ==================================================================
    # Row-level security
    # ==================================================================
    enable_rls(op, TENANT_TABLES)

    # Your own memberships are visible without a tenant. This is not a
    # convenience: it is what makes the policy on `organizations` work at all.
    #
    # That policy says "you can see an org you are a member of", and it says so
    # with an EXISTS against `memberships` — a subquery that is itself subject to
    # `memberships`' own policy, which is tenant-scoped. With no tenant set, the
    # subquery returns nothing, the EXISTS is false, and `GET /orgs` returns an
    # empty list for a user who is an owner of three of them. The policy reads as
    # correct and silently answers "no".
    #
    # Written here, next to the table, rather than in a later migration, because
    # the two policies only make sense read together.
    op.execute(
        """
        CREATE POLICY memberships_own_read ON memberships
            FOR SELECT
            USING (user_id = nullif(current_setting('app.current_user', true), '')::uuid)
        """
    )

    # organizations is special: a user may see the orgs they belong to, and must
    # be able to create one before they belong to anything. Two policies, OR'd.
    op.execute("ALTER TABLE organizations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE organizations FORCE ROW LEVEL SECURITY")

    op.execute(
        """
        CREATE POLICY organizations_member_read ON organizations
            FOR SELECT
            USING (
                id = nullif(current_setting('app.current_org', true), '')::uuid
                OR EXISTS (
                    SELECT 1 FROM memberships m
                     WHERE m.org_id = organizations.id
                       AND m.user_id = nullif(current_setting('app.current_user', true), '')::uuid
                )
            )
        """
    )
    # Signup has no tenant yet. The policy allows an insert, but only when the
    # row is being created by the user who will own it — which the application
    # enforces by always creating the owner membership in the same transaction.
    op.execute(
        """
        CREATE POLICY organizations_insert_by_creator ON organizations
            FOR INSERT
            WITH CHECK (nullif(current_setting('app.current_user', true), '') IS NOT NULL)
        """
    )
    op.execute(
        """
        CREATE POLICY organizations_update_within_tenant ON organizations
            FOR UPDATE
            USING (id = nullif(current_setting('app.current_org', true), '')::uuid)
            WITH CHECK (id = nullif(current_setting('app.current_org', true), '')::uuid)
        """
    )
    op.execute(
        """
        CREATE POLICY organizations_delete_owner_only ON organizations
            FOR DELETE
            USING (
                id = nullif(current_setting('app.current_org', true), '')::uuid
                AND EXISTS (
                    SELECT 1 FROM memberships m
                     WHERE m.org_id = organizations.id
                       AND m.user_id = nullif(current_setting('app.current_user', true), '')::uuid
                       AND m.role = 'owner'
                )
            )
        """
    )

    # The Stripe webhook arrives with no session, no user and no tenant — just a
    # body signed with a shared secret. `billing_customer_id` is how the org is
    # resolved, and this policy is what lets that read happen without handing
    # the application a general SELECT on every organisation. The signature is
    # the credential; the customer id is what it authorises looking up.
    op.execute(
        """
        CREATE POLICY organizations_billing_lookup ON organizations
            FOR SELECT
            USING (
                billing_customer_id = nullif(current_setting('app.current_billing_customer', true), '')
            )
        """
    )

    # users is not org-scoped, so it gets a narrower rule: you can see yourself,
    # and you can see people you share an org with. Not everyone — that would
    # make the users table a directory of every customer.
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY users_self_or_co_member ON users
            FOR SELECT
            USING (
                id = nullif(current_setting('app.current_user', true), '')::uuid
                OR EXISTS (
                    SELECT 1
                      FROM memberships mine
                      JOIN memberships theirs ON theirs.org_id = mine.org_id
                     WHERE mine.user_id = nullif(current_setting('app.current_user', true), '')::uuid
                       AND theirs.user_id = users.id
                )
            )
        """
    )
    # You may create exactly yourself, and edit exactly yourself. Both policies
    # key off `app.current_user`, which the signup path sets to the id it is
    # about to insert. Without the insert policy, signup fails: `users` has RLS
    # and no policy means no rows, for anyone.
    op.execute(
        """
        CREATE POLICY users_self_insert ON users
            FOR INSERT
            WITH CHECK (id = nullif(current_setting('app.current_user', true), '')::uuid)
        """
    )
    op.execute(
        """
        CREATE POLICY users_self_update ON users
            FOR UPDATE
            USING (id = nullif(current_setting('app.current_user', true), '')::uuid)
            WITH CHECK (id = nullif(current_setting('app.current_user', true), '')::uuid)
        """
    )

    # Login has to find a row by email before any user or tenant is known, and
    # there are two ways to allow that:
    #
    #   * a SECURITY DEFINER lookup function, or
    #   * a policy keyed off the thing being looked up.
    #
    # The first one is the idiom, and it is wrong here. This table is FORCE
    # ROW LEVEL SECURITY, so policies apply to the table's owner too, and a
    # SECURITY DEFINER function runs as its owner — the lookup returns zero rows
    # for every login. On a superuser-owned database (which is what a CI service
    # container gives you) it works, so the bug ships: green pipeline, nobody
    # can log in. It was tried, it returned nothing, and this is the replacement.
    #
    # The GUC is safe to write because the value written is the address the
    # caller already typed. You learn nothing from the row you couldn't learn by
    # asking "does this account exist" — and the hash never leaves the process.
    op.execute(
        """
        CREATE POLICY users_login_lookup ON users
            FOR SELECT
            USING (
                lower(email) = lower(nullif(current_setting('app.current_login_email', true), ''))
            )
        """
    )

    # ------------------------------------------------------------------
    # Grants
    # ------------------------------------------------------------------
    op.execute("GRANT USAGE ON SCHEMA public TO workbench")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO workbench"
    )
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO workbench")
    # Future tables created by migrations get the same grants automatically.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO workbench"
    )


def enable_rls(op, tables: tuple[str, ...]) -> None:
    """
    Turn on row-level security for every tenant table, with the same policy.

    `FORCE` matters more than `ENABLE` and is the one people skip. `ENABLE` makes
    the policies apply to non-owners; `FORCE` makes them apply to the table
    owner too. Without FORCE, running the test suite as the owner — which is what
    happens if you don't create two roles — makes every isolation test pass while
    production behaves differently.

    `USING` covers reads, updates and deletes. `WITH CHECK` covers inserts and
    the new value of an update. Omitting `WITH CHECK` is the other classic: rows
    can be read only by their tenant, but written into any tenant.
    """
    for table in tables:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
                USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
                WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
            """
        )

    # nullif(..., '') is not decoration. `current_setting('x', true)` returns
    # NULL when unset, but an empty string when something set it to ''. Casting
    # '' to uuid raises, which turns a misconfigured request into a 500 rather
    # than a denial. The nullif makes the cast yield NULL, the comparison yields
    # NULL, and no rows match — which is the behaviour you want.


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")

    op.execute("DROP POLICY IF EXISTS organizations_member_read ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_insert_by_creator ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_update_within_tenant ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_delete_owner_only ON organizations")
    op.execute("DROP POLICY IF EXISTS organizations_billing_lookup ON organizations")
    op.execute("DROP POLICY IF EXISTS users_self_or_co_member ON users")
    op.execute("DROP POLICY IF EXISTS users_self_insert ON users")
    op.execute("DROP POLICY IF EXISTS users_self_update ON users")
    op.execute("DROP POLICY IF EXISTS users_login_lookup ON users")
    op.execute("DROP POLICY IF EXISTS memberships_own_read ON memberships")

    op.drop_table("documents")
    op.drop_table("invitations")
    op.drop_table("memberships")
    op.drop_table("users")
    op.drop_table("organizations")

    op.execute("DROP TYPE IF EXISTS invitation_role")
    op.execute("DROP TYPE IF EXISTS membership_role")
