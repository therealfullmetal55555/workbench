"""
Users, sessions, refresh tokens, API keys, password resets.

The refresh-token design is the part worth reading. It's a chain, not a row:
each refresh token points at the one it replaced, so a used token presented again
is detectable rather than merely invalid. See `RefreshToken.looks_like_reuse()`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from workbench.tenancy.models import Membership

from workbench.core.models import Base, SoftDelete, Timestamped, UUIDPrimaryKey
from workbench.tenancy.models import Organization  # noqa: F401 — registers the mapper

STAFF_SOURCES = ("manual", "okta", "invite")


class User(Base, UUIDPrimaryKey, Timestamped, SoftDelete):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Staff flags are deliberately separate from org roles. Conflating "works
    # here" with "admin of this customer's org" is how a departing support agent
    # keeps access to five accounts.
    is_staff: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    staff_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # TOTP secret, encrypted at the application layer before it gets here.
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # `TYPE_CHECKING`-only: `Membership` lives in `workbench.tenancy.models`,
    # which imports this module for the `User` type. A runtime import here is a
    # circular import at module load. SQLAlchemy resolves the annotation after
    # both modules are loaded, and this module is always imported alongside
    # `tenancy.models` — `workbench.models` imports both, and the migrations env
    # imports that.
    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user",
        foreign_keys="Membership.user_id",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        # Email uniqueness is case-insensitive in practice. `lower(email)` as an
        # index expression means the database enforces it, not a normalising
        # function someone forgets to call.
        Index("uq_users_email_lower", func.lower(email), unique=True),
    )

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > datetime.now(UTC)

    @property
    def has_password(self) -> bool:
        """False for SSO-only accounts, which must not be offered a password reset."""
        return self.password_hash is not None

    @property
    def is_staff_active(self) -> bool:
        return self.is_staff and self.is_active and self.staff_since is not None

    @staticmethod
    def normalise_email(email: str) -> str:
        return email.strip().lower()

    def record_login(self) -> None:
        self.last_login_at = datetime.now(UTC)
        self.failed_login_count = 0
        self.locked_until = None

    def record_failure(self, threshold: int = 10, lock_minutes: int = 15) -> bool:
        """
        Increment the failure count and lock if it crosses the threshold.
        Returns True when this failure caused a lock.
        """
        self.failed_login_count += 1
        if self.failed_login_count >= threshold:
            self.locked_until = datetime.now(UTC) + timedelta(minutes=lock_minutes)
            self.failed_login_count = 0
            return True
        return False

    def __repr__(self) -> str:
        return f"<User {self.email}>"


class RefreshToken(Base, UUIDPrimaryKey):
    """
    One link in a rotation chain.

    On login we mint token A. When A is used, it's marked rotated and token B is
    issued with `parent_id = A`. If A is ever presented again, either:

      * someone replayed a stolen token, or
      * the legitimate user's client double-sent.

    Both are worth knowing about, and the second one is why we don't simply
    delete the row on rotation — a deleted row can't tell you it was reused.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Which org the token was minted for. Switching org requires a new token, so
    # a stale tab can't act on the org it used to be pointed at.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )

    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    family_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_refresh_tokens_family_active", "family_id", "revoked_at"),)

    @property
    def is_usable(self) -> bool:
        return (
            self.rotated_at is None
            and self.revoked_at is None
            and self.expires_at > datetime.now(UTC)
        )

    def looks_like_reuse(self) -> bool:
        """Presented a token that was already exchanged or revoked."""
        return self.rotated_at is not None or self.revoked_at is not None

    def rotate(self) -> None:
        self.rotated_at = datetime.now(UTC)

    def revoke(self, reason: str) -> None:
        self.revoked_at = datetime.now(UTC)
        self.revoked_reason = reason

    @staticmethod
    def default_expiry(days: int) -> datetime:
        return datetime.now(UTC) + timedelta(days=days)

    def __repr__(self) -> str:
        state = "usable" if self.is_usable else "closed"
        return f"<RefreshToken user={self.user_id} {state}>"


class ApiKey(Base, UUIDPrimaryKey, Timestamped, SoftDelete):
    """
    A machine credential, scoped to one org and a subset of permissions.

    Keys can never exceed the creator's own role — `scopes` is intersected with
    the role's permissions at creation. A member who mints a key does not get
    billing access through it.
    """

    __tablename__ = "api_keys"

    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    scopes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_usable(self) -> bool:
        if self.revoked_at is not None or self.is_deleted:
            return False
        return not (self.expires_at is not None and self.expires_at <= datetime.now(UTC))

    def revoke(self) -> None:
        self.revoked_at = datetime.now(UTC)

    def __repr__(self) -> str:
        return f"<ApiKey {self.prefix}… org={self.org_id}>"


class PasswordReset(Base, UUIDPrimaryKey):
    """
    Reset tokens are single-use and short-lived, and requesting a new one
    invalidates every outstanding token for that user.
    """

    __tablename__ = "password_resets"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and self.expires_at > datetime.now(UTC)

    @staticmethod
    def default_expiry(minutes: int = 60) -> datetime:
        return datetime.now(UTC) + timedelta(minutes=minutes)


class LoginAttempt(Base, UUIDPrimaryKey):
    """
    Every login attempt, successful or not.

    Kept in the database rather than Redis because it outlives a Redis restart
    and because "show me every attempt on this account since Tuesday" is a
    question you will be asked after an incident, not before.
    """

    __tablename__ = "login_attempts"

    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class StaffImpersonation(Base, UUIDPrimaryKey):
    """
    A staff member acting as a customer, with a hard time limit.

    Read-only by design: impersonation exists so support can see what the
    customer sees. If support needs to *change* something, they ask the customer
    to do it, or they use a documented admin endpoint that is separately audited.
    """

    __tablename__ = "staff_impersonations"

    staff_user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    reason: Mapped[str] = mapped_column(String(400), nullable=False)
    ticket_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        return self.ended_at is None and self.expires_at > datetime.now(UTC)

    def end(self) -> None:
        if self.ended_at is None:
            self.ended_at = datetime.now(UTC)

    def __repr__(self) -> str:
        return f"<Impersonation staff={self.staff_user_id} target={self.target_user_id}>"
