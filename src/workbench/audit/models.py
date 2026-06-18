"""
The audit log.

An audit log you can edit is a log nobody trusts. This one is enforced at three
levels, because any single one of them is defeatable by a determined mistake:

  1. **No ORM mutation.** The model has no `updated_at`, and the repository has
     no update or delete method.
  2. **No SQL grant.** The application role holds `INSERT` and `SELECT` on this
     table and nothing else. An `UPDATE` fails at the database.
  3. **A trigger.** Even the owning role is blocked from updating or deleting,
     so a future migration or a panicked psql session can't quietly rewrite
     history.

The third is the one that actually holds, and it's worth the four extra lines of
SQL. `scripts/check_rls.py` and a test both assert it still exists.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from workbench.core.models import Base, UUIDPrimaryKey

# Events are named `<resource>.<verb>`, past tense, lower case. Boring on
# purpose: these strings end up in filters, dashboards and customer exports, and
# they outlive the code that emits them.
EVENT_KINDS = (
    # organisation
    "org.created",
    "org.updated",
    "org.deleted",
    "org.ownership_transferred",
    "org.onboarding_completed",
    # membership
    "member.invited",
    "member.invitation_accepted",
    "member.invitation_revoked",
    "member.role_changed",
    "member.removed",
    "member.suspended",
    "member.restored",
    # auth
    "user.signed_up",
    "user.logged_in",
    "user.login_failed",
    "user.logged_out",
    "user.password_changed",
    "user.password_reset_requested",
    "user.email_verified",
    "user.totp_enabled",
    "user.totp_disabled",
    # credentials
    "apikey.created",
    "apikey.revoked",
    # billing
    "billing.subscription_created",
    "billing.plan_changed",
    "billing.subscription_canceled",
    "billing.payment_failed",
    "billing.payment_succeeded",
    "billing.overage_recorded",
    # staff
    "staff.plan_overridden",
    "staff.plan_override_cleared",
    "staff.org_viewed",
    "staff.audit_exported",
    "staff.webhook_replayed",
    "staff.impersonation_started",
    "staff.impersonation_ended",
    "staff.org_suspended",
    # data
    "document.created",
    "document.updated",
    "document.deleted",
)

ACTOR_KINDS = ("user", "api_key", "system", "staff", "webhook")


class AuditEvent(Base, UUIDPrimaryKey):
    """
    One row per thing that happened.

    `org_id` is nullable and that is deliberate: signup and login happen before
    an org exists or before one is selected, and dropping those events would
    remove exactly the ones you want most after an incident.

    Note there is no `TenantScoped` mixin here even though the column is named
    `org_id` — the mixin adds a foreign key and a non-null constraint. The RLS
    policy for this table is written by hand in the migration instead, matching
    only when `org_id IS NOT NULL`.
    """

    __tablename__ = "audit_events"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Who. Nullable because a webhook or a scheduled job has no user behind it,
    # and inventing one would make the log lie.
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="system")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_email: Mapped[str | None] = mapped_column(
        String(320),
        nullable=True,
        comment="Denormalised on purpose: a deleted user must not erase who did what",
    )
    # True when a staff member is acting as the customer. Kept next to the actor
    # rather than inferred, so it survives any later change to impersonation.
    impersonated: Mapped[bool] = mapped_column(nullable=False, default=False)
    impersonation_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # What. `target_type` is a free string, not an enum, so it doesn't need a
    # migration every time a new resource appears.
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_label: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
        comment="Human-readable, captured at the time so a rename doesn't rewrite history",
    )

    # Before and after, as they were. Not a diff: diffs are unreadable in a
    # support conversation and impossible to query.
    before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Context.
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Mandatory for staff actions — an override with no reason is an "
            "override nobody can review"
        ),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    __table_args__ = (
        # The query the console actually runs: "everything about this org,
        # newest first".
        Index("ix_audit_events_org_created", "org_id", "created_at"),
        # "everything this user did" — the other one.
        Index("ix_audit_events_actor_created", "actor_id", "created_at"),
        # Staff actions, for the quarterly access review.
        Index(
            "ix_audit_events_staff",
            "created_at",
            postgresql_where="actor_kind = 'staff'",
        ),
    )

    @property
    def is_staff_action(self) -> bool:
        return self.actor_kind == "staff" or self.impersonated

    def describe(self) -> str:
        """One line, for a CSV export or a support reply."""
        who = self.actor_email or self.actor_kind
        what = self.target_label or self.target_id or self.target_type or "—"
        when = self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"{when}  {who}  {self.event}  {what}"

    def __repr__(self) -> str:
        return f"<AuditEvent {self.event} org={self.org_id}>"


def redact(
    payload: dict[str, Any] | None, keys: frozenset[str] | None = None
) -> dict[str, Any] | None:
    """
    Strip sensitive values before they land in `before`/`after`.

    The audit log is append-only, which means a secret written here by accident
    cannot be removed. The only defence is not writing it in the first place.

    Default redaction covers password hashes, tokens, API keys and card data —
    the things that would turn a helpful audit trail into an incident.
    """
    if payload is None:
        return None

    keys = keys or SENSITIVE_KEYS
    redacted: dict[str, Any] = {}

    for key, value in payload.items():
        if key.lower() in keys:
            redacted[key] = "«redacted»"
        elif isinstance(value, dict):
            redacted[key] = redact(value, keys)
        elif isinstance(value, list):
            redacted[key] = [redact(v, keys) if isinstance(v, dict) else v for v in value]
        else:
            redacted[key] = value

    return redacted


SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "new_password",
        "current_password",
        "token",
        "token_hash",
        "secret",
        "secret_hash",
        "api_key",
        "authorization",
        "totp_secret",
        "recovery_codes",
        "card_number",
        "cvc",
        "client_secret",
        "refresh_token",
        "access_token",
        "jwt",
        "stripe_secret_key",
        "webhook_secret",
    }
)


def now() -> datetime:
    return datetime.now(UTC)
