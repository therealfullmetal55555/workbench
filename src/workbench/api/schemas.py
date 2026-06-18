"""
Request and response shapes.

Pydantic models, and the only place in the codebase that decides what a client
is allowed to send. The rules encoded here are the ones that would otherwise be
scattered through routers as `if "role" not in (...)` checks:

  * **Input models have no `org_id`.** The tenant comes from the path and the
    session, never from the body. A field that exists is a field that will
    eventually be trusted, and a client-supplied `org_id` is a cross-tenant
    write waiting for one missing check.
  * **Input models have no `status`, `plan_code`, or `created_at`.** Those are
    facts about the world, set by the world — a webhook or the clock.
  * **Output models are explicit.** Returning the ORM object would serialise
    every column that exists now, including the one somebody adds in six months
    without thinking about who can read it. `password_hash` is the obvious one
    and it is not the only one.

Enum values are validated with `Literal`, so a bad role is a 422 with the list of
valid ones rather than a database `CheckViolation` surfacing as a 500.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

from workbench.billing.plans import PlanCode
from workbench.core.permissions import PERMISSIONS, Role
from workbench.tenancy.models import RESERVED_SLUGS, SLUG_PATTERN

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


# An address we have already stored: shape-checked, not verified as deliverable.
# See the long note on `LoginRequest.email`.
def _looks_like_an_address(value: str) -> str:
    """
    One `@`, something either side, no whitespace, a dot in the domain.

    Not a validation library, and not trying to be: this is the check whose job
    is to stop a typo from looking like a missing account. Everything else — MX
    records, disposable domains, whether the local part is quoted — belongs at
    signup or nowhere.
    """
    local, at, domain = value.partition("@")
    if not at or not local or "." not in domain or any(character.isspace() for character in value):
        raise ValueError("that does not look like an email address")
    return value


PlausibleAddress = Annotated[
    str,
    Field(max_length=320),
    BeforeValidator(lambda value: value.strip().lower() if isinstance(value, str) else value),
    AfterValidator(lambda value: _looks_like_an_address(value)),
]


class Schema(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class ReadSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class SignupRequest(Schema):
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=1024)]
    name: Annotated[str, Field(max_length=200)] = ""
    # Optional: most signups create their first org straight away, and making it
    # a second request means the user has a session but nothing to do with it.
    org_name: Annotated[str | None, Field(max_length=120)] = None
    org_slug: Annotated[str | None, Field(max_length=64)] = None

    @field_validator("name", "org_name", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class LoginRequest(Schema):
    # Note: a plain string, not `EmailStr`, and the difference is deliberate.
    #
    # `EmailStr` from `email-validator` checks *deliverability*, which includes
    # refusing the special-use TLDs: `.test`, `.invalid`, `.local`, `.example`.
    # That is the right check for signup — we are about to send mail to that
    # address and there is no point accepting one that cannot receive it.
    #
    # It is the wrong check for login. The address is already in the database;
    # all this request does is name a row. Re-validating deliverability means an
    # account created before the rule changed can never be signed into, and every
    # fixture and staging environment that uses `.test` addresses — the TLD that
    # exists *for* this — gets a 422 that reads like a malformed request.
    #
    # So: an address that is plausible, normalised the same way storage
    # normalises it, and no opinion about DNS.
    email: PlausibleAddress
    password: Annotated[str, Field(max_length=1024)]
    # Which org to mint the token for. Optional: a user in one org shouldn't
    # have to know its id, and the login response lists them anyway.
    org_id: uuid.UUID | None = None


class RefreshRequest(Schema):
    refresh_token: str = Field(min_length=16, max_length=512)
    # Lets a client narrow the new token to a different org it belongs to,
    # without a second round trip. Verified against the membership table.
    org_id: uuid.UUID | None = None


class LogoutRequest(Schema):
    refresh_token: str | None = Field(default=None, max_length=512)
    all_devices: bool = False


class TokenPair(ReadSchema):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    scope: str = ""


class UserOut(ReadSchema):
    id: uuid.UUID
    email: str
    name: str
    is_staff: bool
    email_verified_at: datetime | None = None
    created_at: datetime


class MembershipOut(ReadSchema):
    org_id: uuid.UUID
    org_slug: str | None = None
    org_name: str | None = None
    role: Role
    joined_at: datetime


class MeOut(ReadSchema):
    user: UserOut
    memberships: list[MembershipOut]
    active_org_id: uuid.UUID | None = None
    permissions: list[str] = Field(default_factory=list)
    impersonating: bool = False


class PasswordChangeRequest(Schema):
    current_password: Annotated[str, Field(max_length=1024)]
    new_password: Annotated[str, Field(min_length=8, max_length=1024)]


class PasswordResetRequest(Schema):
    email: PlausibleAddress


class PasswordResetConfirm(Schema):
    token: Annotated[str, Field(min_length=16, max_length=512)]
    new_password: Annotated[str, Field(min_length=8, max_length=1024)]


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------


class OrgCreate(Schema):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    slug: Annotated[str | None, Field(max_length=64)] = None

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, value: str | None) -> str | None:
        if value is None:
            return None
        import re

        slug = value.strip().lower()
        if slug in RESERVED_SLUGS:
            raise ValueError(f"'{slug}' is reserved")
        if not re.match(SLUG_PATTERN, slug):
            raise ValueError(
                "slug must be 3–64 characters of lowercase letters, digits and dashes, "
                "and cannot start or end with a dash"
            )
        return slug


class OrgUpdate(Schema):
    """Note what is absent: `slug` and `overrides`. The first is in every URL a
    customer has bookmarked; the second is a commercial term that only staff
    may write, and it is audited separately."""

    name: Annotated[str | None, Field(min_length=1, max_length=120)] = None
    settings: dict[str, Any] | None = None


class OrgOut(ReadSchema):
    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    onboarding_completed_at: datetime | None = None
    created_at: datetime


class OrgWithRole(OrgOut):
    role: Role


class TransferRequest(Schema):
    to_user_id: uuid.UUID


# ---------------------------------------------------------------------------
# Members and invitations
# ---------------------------------------------------------------------------


class MemberOut(ReadSchema):
    user_id: uuid.UUID
    email: str
    name: str
    role: Role
    joined_at: datetime
    last_login_at: datetime | None = None
    is_active: bool = True


class InviteRequest(Schema):
    email: EmailStr
    role: Literal["admin", "member", "viewer"] = "member"
    # A message from the inviter, appended to the email. Deliberately short:
    # anything longer becomes a place to paste a password.
    note: Annotated[str | None, Field(max_length=500)] = None


class InvitationOut(ReadSchema):
    id: uuid.UUID
    email: str
    role: Role
    expires_at: datetime
    created_at: datetime
    invited_by_id: uuid.UUID
    # Returned exactly once, on creation. Not stored in plaintext, so this is
    # the only time it can be shown.
    token: str | None = None


class AcceptInvitationRequest(Schema):
    name: Annotated[str | None, Field(max_length=200)] = None
    password: Annotated[str | None, Field(min_length=8, max_length=1024)] = None


class RoleUpdate(Schema):
    role: Role


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class ApiKeyCreate(Schema):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: Annotated[int | None, Field(ge=1, le=3650)] = None

    @field_validator("scopes")
    @classmethod
    def _known_scopes(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(PERMISSIONS))
        if unknown:
            raise ValueError(
                f"unknown scope(s): {', '.join(unknown)}. "
                f"Valid scopes are: {', '.join(sorted(PERMISSIONS))}"
            )
        return sorted(set(value))


class ApiKeyOut(ReadSchema):
    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    # The only time the secret exists outside the caller's clipboard.
    secret: str


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


class CheckoutRequest(Schema):
    plan_code: PlanCode
    success_url: str | None = None
    cancel_url: str | None = None


class PortalRequest(Schema):
    return_url: str | None = None


class UsageOut(ReadSchema):
    seats: int = 0
    requests_this_month: int = 0
    tokens: int = 0
    storage_bytes: int = 0
    compute_seconds: int = 0
    ratio: float = 0.0
    over_quota: bool = False


class EntitlementsOut(ReadSchema):
    plan: dict[str, Any]
    limits: dict[str, Any]
    features: list[str]
    usage: dict[str, Any]
    remaining: dict[str, Any]
    overage: str
    is_read_only: bool
    read_grace_days: int
    overrides: list[str]
    subscription: dict[str, Any] | None = None


class PlanOut(ReadSchema):
    code: str
    name: str
    description: str
    limits: dict[str, Any]
    features: list[str]
    overage: str


# ---------------------------------------------------------------------------
# Staff console
# ---------------------------------------------------------------------------


class OrgSummaryOut(ReadSchema):
    id: uuid.UUID
    name: str
    slug: str
    plan_code: str
    status: str
    seats: int
    requests_this_month: int
    is_active: bool
    created_at: datetime


class OverrideRequest(Schema):
    values: dict[str, Any]
    # Mandatory, and the schema is where that is enforced. An override without a
    # reason is an override nobody can review in six months, and this is the
    # field that makes the review possible.
    reason: Annotated[str, Field(min_length=10, max_length=400)]
    expires_in_days: Annotated[int | None, Field(ge=1, le=3650)] = None


class ImpersonateRequest(Schema):
    target_user_id: uuid.UUID
    org_id: uuid.UUID | None = None
    reason: Annotated[str, Field(min_length=10, max_length=400)]
    ticket_ref: Annotated[str | None, Field(max_length=120)] = None
    minutes: Annotated[int | None, Field(ge=1, le=60)] = None


class ImpersonationOut(ReadSchema):
    id: uuid.UUID
    target_user_id: uuid.UUID
    target_org_id: uuid.UUID | None
    expires_at: datetime
    reason: str
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    read_only: bool = True


# ---------------------------------------------------------------------------
# Documents — the sample tenant resource
# ---------------------------------------------------------------------------


class DocumentCreate(Schema):
    title: Annotated[str, Field(min_length=1, max_length=300)]
    body: Annotated[str, Field(max_length=100_000)] = ""


class DocumentUpdate(Schema):
    title: Annotated[str | None, Field(min_length=1, max_length=300)] = None
    body: Annotated[str | None, Field(max_length=100_000)] = None


class DocumentOut(ReadSchema):
    id: uuid.UUID
    title: str
    body: str
    created_by_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEventOut(ReadSchema):
    id: uuid.UUID
    event: str
    actor_kind: str
    actor_id: uuid.UUID | None = None
    actor_email: str | None = None
    impersonated: bool
    target_type: str | None = None
    target_id: str | None = None
    target_label: str | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    ip_address: str | None = None
    request_id: str | None = None
    reason: str | None = None
    created_at: datetime


class AuditExportOut(ReadSchema):
    format: Literal["json", "csv"] = "json"
    url: str
    expires_at: datetime


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------


class PageOut(ReadSchema):
    next_cursor: str | None = None
    has_more: bool = False
    limit: int = 50
    count: int = 0


class DeletedOut(ReadSchema):
    id: uuid.UUID
    deleted: bool = True
    hard: bool = False


class HealthOut(ReadSchema):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    checks: dict[str, str] = Field(default_factory=dict)
