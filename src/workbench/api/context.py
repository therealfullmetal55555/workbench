"""
Who is asking, and on whose behalf.

One function, `resolve_principal`, turns an `Authorization` header into a
`Principal` — a frozen value the rest of the request can read without touching
the database again. Two credential types arrive at it:

  **Bearer JWT** — a human, with an org they were looking at and a `ver` claim
    that a password change can bump.

  **API key** — `wb_live_<lookup>_<secret>`, a machine. The prefix is indexed and
    looked up; the secret is compared in constant time against a stored hash.

Both paths go through the database once. That round trip is what makes the
permission decision current: a membership demoted thirty seconds ago produces a
403 now, even though the token in flight still says `owner`. Caching the role in
the token would make the product feel faster and would keep an ex-employee's
access alive for as long as the token lives.

Nothing here trusts the token for authorisation. The token says *who*; the
database says *what they may do*; and where they disagree, the database wins.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from workbench.api.errors import Forbidden, InvalidToken, Unauthorized
from workbench.audit.models import AuditEvent  # noqa: F401 — registers the mapper
from workbench.auth.models import ApiKey, StaffImpersonation, User
from workbench.auth.passwords import parse_api_key, verify_token
from workbench.auth.tokens import TokenError, claims_org_id, claims_user_id, decode_access_token
from workbench.core.db import CREDENTIAL_SETTING, LOGIN_EMAIL_SETTING, set_tenant
from workbench.core.permissions import Permission, permissions_for
from workbench.tenancy.models import Membership

log = logging.getLogger(__name__)

API_KEY_PREFIX = "wb_"


@dataclass(slots=True)
class Principal:
    """
    The caller, resolved.

    `scopes` is what this credential may do, which is not always what the user
    may do: an API key can only ever be narrower than the person who minted it.
    """

    user: User | None = None
    api_key: ApiKey | None = None
    org_id: uuid.UUID | None = None
    role: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    impersonation: StaffImpersonation | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.user is not None or self.api_key is not None

    @property
    def is_staff(self) -> bool:
        return bool(self.user and self.user.is_staff)

    @property
    def is_impersonating(self) -> bool:
        return self.impersonation is not None and self.impersonation.is_active

    @property
    def actor_id(self) -> uuid.UUID | None:
        """
        Who is acting, for a request that arrived with an API key.

        An API key has no user of its own, so the actor is whoever minted it —
        their membership is what the request is authorised against, their role is
        what the scopes were narrowed by, and their id is what the audit log
        records. Returning `None` here is what made every key-authenticated
        request fail the membership check in `org_scope` with "you are not a
        member of this organisation", which is a confusing way to say "the
        principal forgot its own identity".
        """
        if self.user is not None:
            return self.user.id
        return self.api_key.created_by_id if self.api_key is not None else None

    @property
    def credential_kind(self) -> str:
        if self.api_key is not None:
            return "api_key"
        if self.is_impersonating:
            return "staff"
        return "user" if self.user else "anonymous"

    def can(self, permission: Permission) -> bool:
        return permission in self.scopes

    def describe(self) -> str:
        """For the audit log's actor_email field, which has to survive deletion."""
        if self.api_key is not None:
            return f"{self.api_key.prefix}…"
        return self.user.email if self.user else "anonymous"

    def __repr__(self) -> str:
        return (
            f"<Principal {self.credential_kind} org={self.org_id} role={self.role} "
            f"scopes={len(self.scopes)}>"
        )


async def resolve_principal(
    authorization: str | None,
    factory: async_sessionmaker[AsyncSession],
    *,
    ip_address: str | None = None,
) -> Principal:
    """
    Resolve the credential in the `Authorization` header.

    A missing header is not an error — plenty of endpoints are public, and
    deciding that is the route's job, not this function's. A *malformed* or
    *expired* one is an error, and it must be a 401 rather than an anonymous
    request that later gets a confusing 403.
    """
    if not authorization:
        return Principal()

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Unauthorized("Authorization header must be 'Bearer <token>'")
    token = token.strip()

    if token.startswith(API_KEY_PREFIX):
        return await _resolve_api_key(token, factory, ip_address=ip_address)
    return await _resolve_jwt(token, factory)


# ---------------------------------------------------------------------------
# Bearer tokens: people
# ---------------------------------------------------------------------------


async def _resolve_jwt(token: str, factory: async_sessionmaker[AsyncSession]) -> Principal:
    try:
        claims = decode_access_token(token)
        user_id = claims_user_id(claims)
        org_id = claims_org_id(claims)
    except TokenError as exc:
        # The reason is logged and not returned. "expired" tells a client to
        # refresh; "bad signature" tells an attacker their forgery was seen.
        log.info("access token rejected", extra={"reason": exc.reason})
        raise InvalidToken("the access token is missing, expired, or not valid") from exc

    async with factory() as session, session.begin():
        # `users` is behind FORCE RLS with a self-or-co-member policy, so a
        # request with no tenant can only read the row it claims to be. That
        # is the whole reason the setting exists; see the migration comment.
        await _set_setting(session, "app.current_user", str(user_id))
        if org_id is not None:
            await set_tenant(session, org_id, actor_id=user_id)

        user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is None or not user.is_active or user.is_deleted:
            raise InvalidToken("the account for this token is not active")

        role: str | None = None
        if org_id is not None:
            role = await _membership_role(session, user_id, org_id)
            if role is None:
                # The token names an org the user is no longer in. That is
                # not a permissions problem to be papered over with a 403 on
                # the endpoint — the token itself is stale.
                raise Forbidden(
                    "this token was issued for an organisation you are no longer a member of; "
                    "sign in again"
                )

        principal = Principal(
            user=user,
            org_id=org_id,
            role=role,
            scopes=permissions_for(role) if role else frozenset(),
        )

        impersonation_id = claims.get("imp")
        if impersonation_id:
            principal.impersonation = await _load_impersonation(session, impersonation_id, user_id)
            if principal.impersonation is None:
                raise InvalidToken("the impersonation session has ended")

        return principal


async def _membership_role(
    session: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID
) -> str | None:
    statement = select(Membership.role).where(
        Membership.user_id == user_id,
        Membership.org_id == org_id,
        Membership.suspended_at.is_(None),
    )
    return (await session.execute(statement)).scalar_one_or_none()


async def _load_impersonation(
    session: AsyncSession, impersonation_id: str, staff_user_id: uuid.UUID
) -> StaffImpersonation | None:
    try:
        parsed = uuid.UUID(str(impersonation_id))
    except (ValueError, TypeError):
        return None

    statement = select(StaffImpersonation).where(
        StaffImpersonation.id == parsed,
        StaffImpersonation.staff_user_id == staff_user_id,
    )
    record = (await session.execute(statement)).scalar_one_or_none()
    if record is None or not record.is_active:
        return None
    return record


# ---------------------------------------------------------------------------
# API keys: machines
# ---------------------------------------------------------------------------


async def _resolve_api_key(
    token: str, factory: async_sessionmaker[AsyncSession], *, ip_address: str | None = None
) -> Principal:
    parsed = parse_api_key(token)
    if parsed is None:
        raise InvalidToken("the API key is not in the expected format")

    prefix, secret = parsed
    async with factory() as session, session.begin():
        # The prefix is a credential too, in the sense that holding it is
        # what permits finding the row: the policy `api_keys_by_prefix`
        # matches on exactly this setting. Nobody can enumerate keys.
        await _set_setting(session, CREDENTIAL_SETTING, prefix)

        key = (
            await session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
        ).scalar_one_or_none()

        # Constant-time compare against the stored hash, and the same
        # response whether the prefix was unknown or the secret was wrong.
        # The two mistakes must not be distinguishable from outside.
        if key is None or not verify_token(secret, key.secret_hash):
            log.warning("api key rejected", extra={"prefix": prefix, "ip": ip_address})
            raise InvalidToken("the API key is not valid")

        if not key.is_usable:
            raise InvalidToken("the API key has been revoked or has expired")

        # Now the org is known, so the tenant can be set and the key's
        # authorisation resolved against the *current* role of whoever
        # minted it. A member who was demoted to viewer does not keep
        # write access through a key they created last month.
        await set_tenant(session, key.org_id, actor_id=key.created_by_id)
        role = (
            await _membership_role(session, key.created_by_id, key.org_id)
            if key.created_by_id
            else None
        )
        if key.created_by_id is None:
            # The creator was deleted; a key with no owner has no authority
            # to stand on, so it dies with them.
            raise InvalidToken("the owner of this API key no longer has access")

        granted = permissions_for(role) if role else frozenset()
        scopes = frozenset(set(key.scopes) & set(granted))

        key.last_used_at = datetime.now(UTC)
        key.last_used_ip = ip_address

        return Principal(
            api_key=key,
            org_id=key.org_id,
            role=role,
            scopes=scopes,
        )


async def _set_setting(session: AsyncSession, key: str, value: str) -> None:
    """`set_config(..., is_local => true)` — transaction-scoped, parameterised."""
    await session.execute(
        text("SELECT set_config(:key, :value, true)"), {"key": key, "value": value}
    )


# `LOGIN_EMAIL_SETTING` is imported by the auth router from core.db; referenced
# here so the module's public surface lists every setting this layer writes.
__all__ = ["Principal", "resolve_principal", "LOGIN_EMAIL_SETTING"]
