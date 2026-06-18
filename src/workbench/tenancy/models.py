"""
Organisations, memberships, invitations.

The shape worth noticing: `User` and `Organization` are joined by `Membership`
rather than a foreign key. One user, many orgs, a different role in each. A
`user.org_id` column is simpler right up until the first customer asks for a
consultant to have access to two accounts, and then it's a migration under load.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from workbench.core.models import Base, Timestamped, UUIDPrimaryKey

if TYPE_CHECKING:
    from workbench.auth.models import User

ROLE_VALUES = ("owner", "admin", "member", "viewer")

# A slug is in URLs, so it has to be boring: lowercase, digits, dashes.
SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"

RESERVED_SLUGS = frozenset(
    {
        "admin",
        "api",
        "app",
        "auth",
        "billing",
        "docs",
        "health",
        "help",
        "internal",
        "login",
        "logout",
        "me",
        "new",
        "orgs",
        "settings",
        "signup",
        "staff",
        "static",
        "status",
        "support",
        "system",
        "webhooks",
        "workbench",
        "www",
    }
)


class Organization(Base, UUIDPrimaryKey, Timestamped):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    # The public-facing flag. An org that hasn't finished onboarding shouldn't
    # appear in search, be invoiceable, or count against anything.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    onboarding_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Which billing provider's customer object this org maps to. Nullable
    # because free orgs never touch Stripe, and forcing a Stripe customer at
    # signup means a network call in the signup path.
    billing_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Anything a sales deal carries that the plan catalogue can't express.
    # Read by entitlement resolution, written only by staff, always audited.
    overrides: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy="selectin"
    )
    invitations: Mapped[list[Invitation]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(f"slug ~ '{SLUG_PATTERN}'", name="slug_format"),
        Index("ix_organizations_active_slug", "is_active", "slug"),
    )

    @validates("slug")
    def _reject_reserved_slug(self, _key: str, value: str) -> str:
        slug = value.strip().lower()
        if slug in RESERVED_SLUGS:
            raise ValueError(f"'{slug}' is reserved — pick another slug")
        return slug

    @property
    def is_onboarded(self) -> bool:
        return self.onboarding_completed_at is not None

    def complete_onboarding(self) -> None:
        self.onboarding_completed_at = datetime.now(UTC)

    @staticmethod
    def slugify(name: str) -> str:
        import re

        slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
        return (slug or "org")[:64]

    def __repr__(self) -> str:
        return f"<Organization {self.slug}>"


class Membership(Base, UUIDPrimaryKey, Timestamped):
    """
    The join between a user and an org, carrying the role.

    `joined_at` is separate from `created_at` because an invitation that is
    accepted a week later should read as the day the person started, not the day
    the invite was sent.
    """

    __tablename__ = "memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Denormalised so the unique constraint below can exist. Without it, the
    # constraint would have to be enforced in Python, and two concurrent invites
    # would both succeed.
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        Enum(*ROLE_VALUES, name="membership_role"), nullable=False, default="member"
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # A membership can be suspended without deleting it, so restoring access
    # doesn't lose the audit history of when it was first granted.
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(foreign_keys=[user_id], lazy="joined")

    __table_args__ = (
        # The constraint that makes "invite twice" impossible rather than unlikely.
        UniqueConstraint("user_id", "org_id", name="uq_memberships_user_id_org_id"),
        Index("ix_memberships_org_role", "org_id", "role"),
    )

    @property
    def is_active(self) -> bool:
        return self.suspended_at is None

    def __repr__(self) -> str:
        return f"<Membership user={self.user_id} org={self.org_id} role={self.role}>"


class Invitation(Base, UUIDPrimaryKey, Timestamped):
    """
    A pending invitation.

    Three things this gets right that naive invitations don't:

    1. The token is stored **hashed**. Invitations travel by email and land in
       inboxes; a database dump should not let anyone accept them.
    2. Acceptance requires the signed-in email to match the invited email. A
       forwarded link is not a grant.
    3. `accepted_at` is set once and can't be reset, so a replayed link is a 409
       rather than a second membership.
    """

    __tablename__ = "invitations"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    role: Mapped[str] = mapped_column(
        Enum(*ROLE_VALUES, name="invitation_role"), nullable=False, default="member"
    )

    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    invited_by_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    send_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    organization: Mapped[Organization] = relationship(back_populates="invitations")

    __table_args__ = (
        # Only one live invitation per email per org. A partial index, because
        # accepted and revoked rows should accumulate as history.
        Index(
            "uq_invitations_pending_email",
            "org_id",
            "email",
            unique=True,
            postgresql_where="accepted_at IS NULL AND revoked_at IS NULL",
        ),
    )

    @staticmethod
    def new_token() -> tuple[str, str]:
        """Returns (plaintext, hash). Only the hash is stored; the plaintext is emailed."""
        from workbench.auth.passwords import hash_token

        token = secrets.token_urlsafe(32)
        return token, hash_token(token)

    @property
    def is_pending(self) -> bool:
        return self.accepted_at is None and self.revoked_at is None and not self.is_expired

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= datetime.now(UTC)

    def accept(self, user_id: uuid.UUID) -> None:
        if not self.is_pending:
            raise ValueError("invitation is no longer pending")
        self.accepted_at = datetime.now(UTC)
        self.accepted_by_id = user_id

    def revoke(self, by_user_id: uuid.UUID) -> None:
        self.revoked_at = datetime.now(UTC)
        self.revoked_by_id = by_user_id

    @staticmethod
    def default_expiry(hours: int) -> datetime:
        return datetime.now(UTC) + timedelta(hours=hours)

    def __repr__(self) -> str:
        state = "pending" if self.is_pending else "closed"
        return f"<Invitation {self.email} → {self.org_id} ({state})>"
