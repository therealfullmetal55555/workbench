"""
Billing storage.

The models here hold **state**, not **policy**. The plan catalogue lives in
`plans.py` and the resolution rules in `entitlements.py`; this file is only
about what's true of a particular customer's subscription right now.

Two tables carry most of the weight:

* `stripe_events` — the idempotency ledger. An event id that has been seen is
  unique in the table, so the second delivery of the same webhook can't be
  applied twice. Stripe retries; this is why you don't send four upgrade emails.
* `usage_records` — metered consumption, one row per org per period per meter,
  incremented inside the transaction that did the work.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from workbench.core.models import Base, Timestamped, UUIDPrimaryKey

SUBSCRIPTION_STATUSES = (
    "active",
    "trialing",
    "past_due",
    "unpaid",
    "canceled",
    "incomplete",
    "incomplete_expired",
)

USAGE_METERS = ("requests", "tokens", "storage_bytes", "seats", "compute_seconds")


class Subscription(Base, UUIDPrimaryKey, Timestamped):
    """
    One row per org. Not per subscription object in Stripe.

    History lives in `stripe_events` and the audit log, not as a stack of rows
    here. "What is this customer paying for right now" is asked on every
    request; "what did they pay for in March" is asked once a quarter by one
    person. Optimise for the first and let the second read the event log.
    """

    __tablename__ = "subscriptions"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="stripe")
    external_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        unique=True,
        index=True,
        comment=(
            "Stripe subscription id. Nullable: a plan override can exist with no subscription."
        ),
    )
    external_customer_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    external_price_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    plan_code: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="free",
        index=True,
        comment="Matches a key in plans.CATALOGUE. Unknown values resolve to free.",
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="none", index=True)

    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_period_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    current_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # The ordering clock: the `created` timestamp of the newest event folded into
    # this row, and the id of the event itself. Without these the state machine
    # cannot tell last week's redelivery from this morning's upgrade — it can only
    # apply whatever arrived most recently, which is the one thing about webhooks
    # you can rely on being wrong.
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Stripe's own view, kept verbatim for support. When a customer says "your
    # page shows active but I cancelled", this is the row that settles it.
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")

    __table_args__ = (
        CheckConstraint(
            "status IN ('" + "','".join(SUBSCRIPTION_STATUSES) + "')",
            name="status_valid",
        ),
        CheckConstraint("quantity >= 1", name="quantity_positive"),
        Index("ix_subscriptions_status_period", "status", "current_period_end"),
    )

    @property
    def is_in_grace(self) -> bool:
        """A cancellation scheduled for period end, still entitled until then."""
        return self.cancel_at_period_end and (
            self.current_period_end is None or self.current_period_end > datetime.now(UTC)
        )

    def __repr__(self) -> str:
        return f"<Subscription org={self.org_id} {self.plan_code}/{self.status}>"


class StripeEvent(Base, UUIDPrimaryKey):
    """
    The idempotency ledger.

    Process, in this order, inside one transaction:

        1. INSERT the event id. If this raises a unique violation, the event has
           been handled already — roll back and return 200.
        2. Do the work.
        3. Commit.

    Doing the work first and *then* recording it is the version that sends the
    upgrade email twice, because the crash between step 2 and step 3 means Stripe
    retries and you run it again.

    Kept forever rather than pruned. It's one narrow row per event, and a
    duplicate charge is more expensive than the storage.
    """

    __tablename__ = "stripe_events"

    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False, index=True)

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    @property
    def is_processed(self) -> bool:
        return self.processed_at is not None

    @property
    def needs_retry(self) -> bool:
        return self.processed_at is None and self.attempts < 8

    def __repr__(self) -> str:
        state = "processed" if self.is_processed else f"attempts={self.attempts}"
        return f"<StripeEvent {self.event_type} {state}>"


class UsageRecord(Base, UUIDPrimaryKey, Timestamped):
    """
    Metered consumption, one row per (org, meter, period).

    Incremented with an atomic `UPDATE ... SET quantity = quantity + :n` inside
    the transaction that did the work, so a rollback un-counts it. Recording
    usage in Redis and reconciling later sounds faster and produces a month where
    the numbers don't match — which is the month a customer disputes their
    invoice and you have no answer.
    """

    __tablename__ = "usage_records"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    meter: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    quantity: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    included: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
        comment=(
            "The allowance at the time, snapshotted so a plan change mid-period "
            "doesn't rewrite history"
        ),
    )
    reported_to_provider_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    provider_record_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        # One row per meter per period. The constraint that makes the atomic
        # increment possible.
        UniqueConstraint(
            "org_id", "meter", "period_start", name="uq_usage_records_org_id_meter_period_start"
        ),
        CheckConstraint("quantity >= 0", name="quantity_non_negative"),
        Index("ix_usage_records_org_meter_period", "org_id", "meter", "period_start"),
    )

    @property
    def overage(self) -> int:
        return max(0, self.quantity - self.included)

    @property
    def is_settled(self) -> bool:
        return self.reported_to_provider_at is not None or self.overage == 0

    def __repr__(self) -> str:
        return f"<UsageRecord {self.meter}={self.quantity} org={self.org_id}>"


class PlanOverride(Base, UUIDPrimaryKey, Timestamped):
    """
    A staff-authored change to an org's entitlements, with a reason and an owner.

    Duplicated from `Organization.overrides` (which is the JSON the resolver
    reads) so that "who gave this customer 500 seats, when, and why" is a
    queryable row rather than a JSON key with no history. The JSON blob is the
    fast path; this table is the record.
    """

    __tablename__ = "plan_overrides"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    applied_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    values: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(String(400), nullable=False)

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "A trial extension should expire on its own; a forgotten override is a "
            "permanent discount"
        ),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > datetime.now(UTC)

    def __repr__(self) -> str:
        return f"<PlanOverride org={self.org_id} keys={sorted(self.values)}>"


class DunningAttempt(Base, UUIDPrimaryKey):
    """
    One row per recovery email for a failed payment.

    Exists so the sequence can't loop forever and so support can see exactly
    which messages a customer has already received before they call in angry.
    """

    __tablename__ = "dunning_attempts"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=True
    )

    step: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    template: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "org_id", "step", "sent_at", name="uq_dunning_attempts_org_id_step_sent_at"
        ),
    )
