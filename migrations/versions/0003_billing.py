"""billing: subscriptions, usage, overrides, dunning, and the Stripe event ledger

Revision ID: 0003_billing
Revises: 0002_identity
Create Date: 2026-09-29

Four tenant tables and one that deliberately is not.

`stripe_events` carries an `org_id` and has **no row level security**. That is a
decision, not an oversight, and `scripts/check_rls.py` has an exemptions list
that makes it a decision somebody has to look at:

  The webhook writes the event id *before* it does the work, which is the whole
  mechanism of idempotency, and at that moment the org may not be resolved yet —
  a `customer.subscription.created` for a customer we have never seen is exactly
  the case the ledger exists to survive. A policy keyed on the tenant cannot
  apply to a row written before the tenant is known.

  What it does contain is Stripe's own payloads, so it is not nothing: the app
  role can read every customer's invoices from it. The mitigations are that only
  the webhook path touches it, that path takes no user input beyond a
  signature-verified body, and the query is always by `event_id`. If that stops
  being true, this table needs the same treatment as the rest.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_billing"
down_revision = "0002_identity"
branch_labels = None
depends_on = None

APP_ROLE = "workbench"

TENANT_TABLES = ("subscriptions", "usage_records", "plan_overrides", "dunning_attempts")

SUBSCRIPTION_STATUSES = (
    "active", "trialing", "past_due", "unpaid", "canceled", "incomplete", "incomplete_expired",
)


def upgrade() -> None:
    # ------------------------------------------------------------------
    # subscriptions
    # ------------------------------------------------------------------
    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="stripe"),
        sa.Column("external_id", sa.String(128), nullable=True,
                  comment="Stripe subscription id. Nullable because a plan override can exist with no subscription."),
        sa.Column("external_customer_id", sa.String(128), nullable=True),
        sa.Column("external_price_id", sa.String(128), nullable=True),
        sa.Column("plan_code", sa.String(32), nullable=False, server_default="free",
                  comment="Matches a key in plans.CATALOGUE. Unknown values resolve to free."),
        sa.Column("status", sa.String(32), nullable=False, server_default="none"),
        sa.Column("quantity", sa.Integer, nullable=False, server_default="1"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
        # The ordering clock. Every field above is a snapshot, and snapshots
        # arrive out of order — Stripe redelivers, retries, and occasionally
        # sends two events in the wrong sequence on purpose. `last_event_at` is
        # the `created` timestamp of the newest event applied to this row, and it
        # is Stripe's clock rather than ours: our receive time is precisely the
        # thing that arrives out of order.
        #
        # These two columns were missing from the first draft of this migration
        # while the state machine wrote to them via `setattr`, which on an
        # unmapped name quietly creates an instance attribute and persists
        # nothing. Everything looked right — the fold happened, the row updated —
        # and the staleness check read `None` on every request, so an out-of-order
        # cancellation was applied on top of an upgrade and the customer who had
        # just paid was left cancelled.
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True,
                  comment="`created` of the newest event folded into this row."),
        sa.Column("last_event_id", sa.String(128), nullable=True,
                  comment="Stripe event id of that event. Kept for support."),
        sa.Column("raw", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('" + "','".join(SUBSCRIPTION_STATUSES) + "')",
            name="ck_subscriptions_status_valid",
        ),
        sa.CheckConstraint("quantity >= 1", name="ck_subscriptions_quantity_positive"),
    )
    op.create_index("ix_subscriptions_org_id", "subscriptions", ["org_id"], unique=True)
    op.create_index("ix_subscriptions_external_id", "subscriptions", ["external_id"], unique=True)
    op.create_index("ix_subscriptions_external_customer_id", "subscriptions", ["external_customer_id"])
    op.create_index("ix_subscriptions_plan_code", "subscriptions", ["plan_code"])
    op.create_index("ix_subscriptions_status", "subscriptions", ["status"])
    op.create_index("ix_subscriptions_status_period", "subscriptions", ["status", "current_period_end"])

    # ------------------------------------------------------------------
    # usage_records
    # ------------------------------------------------------------------
    op.create_table(
        "usage_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("meter", sa.String(32), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("quantity", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("included", sa.BigInteger, nullable=False, server_default="0",
                  comment="The allowance at the time, snapshotted so a plan change mid-period doesn't rewrite history"),
        sa.Column("reported_to_provider_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_record_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("quantity >= 0", name="ck_usage_records_quantity_non_negative"),
        sa.UniqueConstraint("org_id", "meter", "period_start", name="uq_usage_records_org_id_meter_period_start"),
    )
    op.create_index("ix_usage_records_org_id", "usage_records", ["org_id"])
    op.create_index("ix_usage_records_meter", "usage_records", ["meter"])
    op.create_index("ix_usage_records_org_meter_period", "usage_records", ["org_id", "meter", "period_start"])

    # ------------------------------------------------------------------
    # plan_overrides
    # ------------------------------------------------------------------
    op.create_table(
        "plan_overrides",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("applied_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("values", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("reason", sa.String(400), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True,
                  comment="A trial extension should expire on its own; a forgotten override is a permanent discount"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_plan_overrides_org_id", "plan_overrides", ["org_id"])

    # ------------------------------------------------------------------
    # dunning_attempts
    # ------------------------------------------------------------------
    op.create_table(
        "dunning_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("step", sa.Integer, nullable=False, server_default="1"),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("template", sa.String(64), nullable=True),
        sa.UniqueConstraint("org_id", "step", "sent_at", name="uq_dunning_attempts_org_id_step_sent_at"),
    )
    op.create_index("ix_dunning_attempts_org_id", "dunning_attempts", ["org_id"])

    # ------------------------------------------------------------------
    # stripe_events — the idempotency ledger. See the module docstring.
    # ------------------------------------------------------------------
    op.create_table(
        "stripe_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.String(128), nullable=False, unique=True),
        sa.Column("event_type", sa.String(96), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(1000), nullable=True),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_stripe_events_event_id", "stripe_events", ["event_id"], unique=True)
    op.create_index("ix_stripe_events_event_type", "stripe_events", ["event_type"])
    op.create_index("ix_stripe_events_org_id", "stripe_events", ["org_id"])
    op.create_index("ix_stripe_events_received_at", "stripe_events", ["received_at"])

    # ==================================================================
    # Row-level security
    # ==================================================================
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
                USING (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
                WITH CHECK (org_id = nullif(current_setting('app.current_org', true), '')::uuid)
            """
        )

    # Order-independent webhooks need this one. A `customer.subscription.updated`
    # can arrive before the `checkout.session.completed` that would have created
    # the row, and it names the subscription and nothing else we can resolve. So
    # the subscription id is treated as a credential too: the payload proves the
    # subscription exists, and this policy lets that one row be found by it.
    op.execute(
        """
        CREATE POLICY subscriptions_by_external_id ON subscriptions
            FOR SELECT
            USING (external_id = nullif(current_setting('app.current_billing_subscription', true), ''))
        """
    )

    # Maintenance: the reconciliation job correcting drift, and the rollup
    # closing a usage period. Both are system jobs with no tenant — see the note
    # in 0002 for why they get a policy rather than a privileged role.
    maintenance = "nullif(current_setting('app.maintenance', true), '') = 'on'"
    op.execute(
        f"""
        CREATE POLICY subscriptions_maintenance ON subscriptions
            FOR UPDATE
            USING ({maintenance})
            WITH CHECK ({maintenance})
        """
    )
    op.execute(
        f"""
        CREATE POLICY usage_records_maintenance ON usage_records
            FOR INSERT
            WITH CHECK ({maintenance})
        """
    )
    op.execute(
        f"""
        CREATE POLICY usage_records_maintenance_update ON usage_records
            FOR UPDATE
            USING ({maintenance})
            WITH CHECK ({maintenance})
        """
    )

    # The staff console reads these too. See the note in 0002 for why this is a
    # per-table policy rather than a privileged role.
    for table in ("subscriptions", "usage_records", "plan_overrides", "dunning_attempts"):
        op.execute(
            f"""
            CREATE POLICY {table}_staff_read ON {table}
                FOR SELECT
                USING (nullif(current_setting('app.staff', true), '') = 'on')
            """
        )

    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON "
        f"subscriptions, usage_records, plan_overrides, dunning_attempts, stripe_events TO {APP_ROLE}"
    )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_staff_read ON {table}")
    op.execute("DROP POLICY IF EXISTS subscriptions_maintenance ON subscriptions")
    op.execute("DROP POLICY IF EXISTS usage_records_maintenance ON usage_records")
    op.execute("DROP POLICY IF EXISTS usage_records_maintenance_update ON usage_records")
    op.execute("DROP POLICY IF EXISTS subscriptions_by_external_id ON subscriptions")

    op.drop_table("stripe_events")
    op.drop_table("dunning_attempts")
    op.drop_table("plan_overrides")
    op.drop_table("usage_records")
    op.drop_table("subscriptions")
