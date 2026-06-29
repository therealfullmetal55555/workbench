"""
The dependency layer.

Everything a request needs to know about itself is assembled here, once, and
handed to the route as a `Scope`:

    scope = Depends(requires("member:read"))

That single line means four things, in this order:

    1. the caller is authenticated (or the route is public and it says so)
    2. they are a member of the org in the path, with a role
    3. the role holds the permission asked for
    4. they are not over quota on a plan that hard-stops, and the org is not
       read-only after a failed payment

Doing it as one dependency rather than four is not brevity for its own sake. The
mistake this design prevents is a route that takes a session, forgets the
permission check, and works — because the person writing it was an owner, and
owners can do everything. The permission is a required argument, so there is no
version of the route that compiles without one.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Annotated, Any, cast

from fastapi import Depends, Header, Path, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from workbench.api.context import Principal, resolve_principal
from workbench.api.errors import Forbidden, NotFound, ServiceUnavailable, Unauthorized
from workbench.api.ratelimit import RateLimiter
from workbench.billing.entitlements import Entitlements, resolve_from_orm
from workbench.billing.models import Subscription, UsageRecord
from workbench.core.db import STAFF_SETTING, tenant_session
from workbench.core.permissions import Permission, permissions_for
from workbench.core.settings import Settings, get_settings
from workbench.tenancy.models import Membership, Organization

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Process-wide objects, owned by the app's lifespan
# ---------------------------------------------------------------------------


def get_settings_dep() -> Settings:
    return get_settings()


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    """
    The factory built at startup and parked on `app.state`.

    Not a module-level global: a global engine is created at import time, which
    means importing the app opens a connection pool, which means the test
    process and the migration process each hold one.
    """
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:  # pragma: no cover — only reachable if lifespan didn't run
        raise ServiceUnavailable("the application is still starting up")
    return factory


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:  # pragma: no cover
        return RateLimiter.in_memory()
    return limiter


def client_ip(request: Request) -> str | None:
    """
    The caller's address, behind a proxy.

    `X-Forwarded-For` is trusted and `request.client.host` is not used for rate
    limiting without it, because behind a load balancer every request appears to
    come from the balancer — which makes per-IP limits a global limit. The header
    is spoofable, so this value is used for rate limiting and logging only; it is
    never an authorisation input.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client else None


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> Principal:
    return await resolve_principal(authorization, factory, ip_address=client_ip(request))


PrincipalDep = Annotated[Principal, Depends(principal)]


async def require_user(ctx: PrincipalDep) -> Principal:
    if not ctx.is_authenticated:
        raise Unauthorized("this endpoint requires an access token or an API key")
    return ctx


UserDep = Annotated[Principal, Depends(require_user)]


async def require_person(ctx: PrincipalDep) -> Principal:
    """
    A person, not a machine.

    `require_user` accepts any credential, which is right for the endpoints a
    machine may call — listing documents, reporting usage, reading entitlements.
    It is the wrong dependency for the ones that describe *you*: `/auth/me`,
    changing a password, creating an org, accepting an invitation. A key has no
    name, no memberships, no password and no session to log out of, so one
    arriving there is a client error, and the answer should be a 401 that says
    so.

    What it replaced was worse than a wrong status code: an `assert user is not
    None` in the handler. That is a 500 in a normal run and, under `python -O`,
    no check at all plus an AttributeError one line later. An assertion is a note
    to the reader that something cannot happen, not a way to reject a request.
    """
    if not ctx.is_authenticated:
        raise Unauthorized("this endpoint requires an access token")
    if ctx.api_key is not None:
        raise Unauthorized(
            "this endpoint describes a person; an API key is a machine credential. "
            "Call it with an access token, or use the org-scoped endpoints with the key."
        )
    return ctx


PersonDep = Annotated[Principal, Depends(require_person)]


async def staff_scope(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)],
    ctx: Annotated[Principal, Depends(require_staff)],
) -> AsyncIterator[Scope]:
    """
    A no-tenant session that can see across customers.

    `set_config('app.staff', 'on', true)` is the single line that unlocks every
    `*_staff_read` policy. It is written here, once, after `require_staff` has
    checked the flag on the user row — so the thing that decides is a database
    read, not a claim in a token.
    """
    async with tenant_session(factory, None, actor_id=ctx.actor_id, bypass=True) as session:
        await session.execute(
            text("SELECT set_config(:key, :value, true)"),
            {"key": STAFF_SETTING, "value": "on"},
        )
        yield Scope(session=session, principal=ctx, tenant=False)


async def require_staff(ctx: UserDep) -> Principal:
    """
    Staff status, not an org role.

    A staff member is not an owner of anything. They can read across orgs through
    the staff console, with a reason, and every one of those reads is audited —
    which is a different thing from being a member of the customer's org.
    """
    if not ctx.is_staff:
        raise Forbidden("staff access required")
    if ctx.is_impersonating:
        raise Forbidden(
            "an impersonation session cannot use the staff console — end it first, "
            "so the audit log doesn't show staff acting as staff acting as a user"
        )
    return ctx


StaffDep = Annotated[Principal, Depends(require_staff)]


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Scope:
    """
    Everything a route is allowed to touch, for this request.

    Holding a `Scope` means the caller passed every check. The session inside it
    is bound to the tenant in `org_id`, so queries against tenant tables cannot
    return another customer's rows even if the route forgets a filter — Postgres
    is the thing enforcing that, not the route.
    """

    session: AsyncSession
    principal: Principal
    tenant: bool
    org: Organization | None = None
    role: str | None = None
    entitlements: Entitlements | None = None

    @property
    def org_id(self) -> uuid.UUID:
        assert self.org is not None
        return self.org.id

    @property
    def actor(self) -> Principal:
        return self.principal

    @property
    def actor_id(self) -> uuid.UUID | None:
        return self.principal.actor_id

    @property
    def actor_email(self) -> str | None:
        return self.principal.user.email if self.principal.user else None

    def can(self, permission: Permission) -> bool:
        return permission in self.scopes

    @property
    def scopes(self) -> frozenset[Permission]:
        # `Principal.scopes` is typed as `frozenset[str]` because a scope can
        # arrive from a token or a key's stored list; by the time it is on a
        # tenant scope it has been intersected with the role's matrix, so the
        # narrowing here is a statement about where it came from, not a wish.
        return cast("frozenset[Permission]", self.principal.scopes)

    def require_feature(self, feature: str) -> None:
        """Raises `FeatureNotIncluded` (→ 402) when the plan doesn't include it."""
        assert self.entitlements is not None
        self.entitlements.require_feature(feature)

    def require_quota(self, entitlement: str, adding: int = 1) -> None:
        """Raises `QuotaExceeded` (→ 402) when this would cross a hard limit."""
        assert self.entitlements is not None
        self.entitlements.require(entitlement, adding)

    @property
    def is_read_only(self) -> bool:
        return bool(self.entitlements and self.entitlements.is_read_only)


async def system_scope(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)],
    ctx: PrincipalDep,
) -> AsyncIterator[Scope]:
    """
    A session with no tenant.

    For the paths that genuinely have none: signup, login, refresh, the Stripe
    webhook, the staff console. `bypass=True` is the argument that says so, and
    the name is chosen to make a reviewer stop and read the call site.
    """
    async with tenant_session(factory, None, actor_id=ctx.actor_id, bypass=True) as session:
        yield Scope(session=session, principal=ctx, tenant=False)


async def org_scope(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)],
    ctx: PrincipalDep,
    org_id: Annotated[uuid.UUID, Path(alias="org_id")],
) -> AsyncIterator[Scope]:
    """
    A session bound to one organisation, with the caller's role in it.

    The membership lookup is the authorisation step, and it is *inside* the
    tenant session — asking "is this user a member of this org" as the org is
    exactly the question the policy on `memberships` is designed to answer.
    """
    if not ctx.is_authenticated:
        raise Unauthorized("this endpoint requires an access token or an API key")

    async with tenant_session(
        factory, org_id, actor_id=ctx.actor_id, impersonated=ctx.is_impersonating
    ) as session:
        org = (
            await session.execute(select(Organization).where(Organization.id == org_id))
        ).scalar_one_or_none()
        if org is None:
            # Same 404 whether the org doesn't exist or the caller can't see it.
            # The difference is information about other customers.
            raise NotFound("organisation", org_id)

        membership = (
            await session.execute(
                select(Membership).where(
                    Membership.user_id == ctx.actor_id,
                    Membership.org_id == org_id,
                    Membership.suspended_at.is_(None),
                )
            )
        ).scalar_one_or_none()

        role = membership.role if membership else None
        if role is None:
            # An API key carries the role of whoever minted it, so a key is not
            # a way around having been removed from the org.
            raise Forbidden("you are not a member of this organisation")

        # Two credentials, two rules, and the difference is the point.
        #
        # An API key is a deliberately narrowed credential: whoever minted it
        # chose a subset of what they could do, so its scopes are intersected
        # with the owner's *current* role — a demotion narrows the key with it.
        #
        # A person's token is not narrowed. Intersecting here looked like a
        # safety property and was a bug: the scopes resolved at token time are
        # computed for the org the token was minted in, so a token issued before
        # you joined an org carries none of that org's permissions — and a member
        # inviting themselves in and then reading the org's data got a 403 saying
        # the role of 'member' does not hold 'data:read', which it does. The
        # membership is the authorisation; the token is only proof of identity.
        if ctx.api_key is not None:
            scopes = frozenset(set(ctx.scopes) & set(permissions_for(role)))
        else:
            scopes = permissions_for(role)
        scoped = Principal(
            user=ctx.user,
            api_key=ctx.api_key,
            org_id=org_id,
            role=role,
            scopes=scopes,
            impersonation=ctx.impersonation,
        )

        entitlements = await load_entitlements(session, org)

        yield Scope(
            session=session,
            principal=scoped,
            tenant=True,
            org=org,
            role=role,
            entitlements=entitlements,
        )


async def load_entitlements(session: AsyncSession, org: Organization) -> Entitlements:
    """
    Resolve what this org may do, from the three inputs.

    Deliberately reads *usage* rather than trusting a counter on the org row: the
    counter is what drifts, and it drifts upward in the customer's favour, which
    is the direction nobody reports.
    """
    subscription = (
        await session.execute(select(Subscription).where(Subscription.org_id == org.id))
    ).scalar_one_or_none()

    usage_row = (
        (
            await session.execute(
                select(UsageRecord.quantity).where(
                    UsageRecord.org_id == org.id, UsageRecord.meter == "requests"
                )
            )
        )
        .scalars()
        .all()
    )
    requests_used = max(usage_row) if usage_row else 0

    seats_used = (
        (
            await session.execute(
                select(Membership.id).where(
                    Membership.org_id == org.id, Membership.suspended_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )

    return resolve_from_orm(
        org,
        subscription,
        requests_this_month=requests_used,
        seats=len(seats_used),
    )


def requires(
    permission: Permission,
    *,
    write: bool = False,
    feature: str | None = None,
) -> Callable[..., AsyncIterator[Scope]]:
    """
    Build the dependency for one route.

        scope = Depends(requires("billing:write", write=True))

    `write=True` is what turns a failed payment into a 402 instead of a silent
    success: past_due and unpaid orgs drop to read-only, and the route that was
    about to mutate state refuses. Reads keep working through the grace period,
    because a customer who can't export their data before leaving is a customer
    who leaves badly.
    """

    async def dependency(scope: Annotated[Scope, Depends(org_scope)]) -> Scope:
        if not scope.can(permission):
            raise Forbidden(
                f"role '{scope.role}' does not hold permission '{permission}'",
                permission=permission,
                role=scope.role,
                granted=sorted(permissions_for(scope.role or "")),
            )
        if write and scope.principal.is_impersonating:
            # Impersonation is read-only, and this is where that is enforced —
            # in the dependency every writing route already asks for, rather
            # than in thirty route bodies where one of them would be missed.
            raise Forbidden(
                "impersonation sessions are read-only: ask the customer to make the "
                "change, or use the staff console, which is audited separately"
            )
        if feature and scope.entitlements is not None:
            scope.entitlements.require_feature(feature)
        if write and scope.is_read_only:
            raise Forbidden(
                "this organisation is read-only: the subscription is not active. "
                "Reads and exports keep working; writes resume when billing is resolved.",
                subscription_status=(
                    scope.entitlements.subscription.status
                    if scope.entitlements and scope.entitlements.subscription
                    else None
                ),
            )
        return scope

    # FastAPI accepts any callable that returns the scope; the annotation on
    # `requires` describes the dependency as an iterator because that is what
    # most of them are.
    return cast(Any, dependency)


ScopeDep = Annotated[Scope, Depends(org_scope)]
SystemDep = Annotated[Scope, Depends(system_scope)]
StaffScopeDep = Annotated[Scope, Depends(staff_scope)]


__all__ = [
    "Principal",
    "StaffScopeDep",
    "PrincipalDep",
    "Scope",
    "ScopeDep",
    "PersonDep",
    "StaffDep",
    "SystemDep",
    "UserDep",
    "client_ip",
    "get_rate_limiter",
    "get_session_factory",
    "get_settings_dep",
    "load_entitlements",
    "org_scope",
    "principal",
    "staff_scope",
    "require_person",
    "require_staff",
    "require_user",
    "requires",
    "system_scope",
]
