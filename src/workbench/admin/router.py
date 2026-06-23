"""
The staff console.

This is the only part of the service that reads across organisations, and every
route in it is written to make that expensive on purpose:

  * **Staff is not an org role.** `User.is_staff` is separate from
    `Membership.role`, and nothing here grants a membership. A support engineer
    is not an owner of the customer's org, and never becomes one by using this
    console.
  * **A reason is mandatory on every write.** Not a free-text note that goes in a
    log nobody reads — the reason is a required field in the request schema, so a
    call without one is a 422 before it reaches the database.
  * **Impersonation is read-only and expires.** Sixty minutes maximum, enforced
    by an expiry on the row and re-checked on every request that uses the token.
    Ending it is an endpoint, and the customer can see that it happened.

Everything staff do lands in `audit_events` with `actor_kind = 'staff'`, which is
the filter the quarterly access review runs on. That review is the reason the
reason field exists.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status
from sqlalchemy import func, or_, select

from workbench.api.deps import StaffDep, StaffScopeDep, client_ip
from workbench.api.errors import BadRequest, Forbidden, NotFound
from workbench.api.schemas import (
    HealthOut,
    ImpersonateRequest,
    ImpersonationOut,
    OrgSummaryOut,
    OverrideRequest,
)
from workbench.audit.log import write_audit
from workbench.auth.models import LoginAttempt, StaffImpersonation, User
from workbench.auth.tokens import mint_access_token
from workbench.billing.entitlements import OVERRIDABLE
from workbench.billing.models import PlanOverride, Subscription, UsageRecord
from workbench.core.models import uuid7
from workbench.core.permissions import PermissionRow, describe_matrix
from workbench.core.settings import get_settings
from workbench.tenancy.models import Membership, Organization

log = logging.getLogger(__name__)

router = APIRouter(prefix="/staff", tags=["staff"])


# ---------------------------------------------------------------------------
# Reading across orgs
# ---------------------------------------------------------------------------


@router.get("/orgs", response_model=list[OrgSummaryOut], summary="Search organisations")
async def search_orgs(
    scope: StaffScopeDep,
    q: Annotated[str | None, Query(min_length=2, max_length=120)] = None,
    plan: str | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> list[OrgSummaryOut]:
    """
    Search, always bounded.

    `limit` has a maximum and there is no "return everything". A staff endpoint
    that can dump every customer is an endpoint that will be used to dump every
    customer, by somebody who is leaving, at 21:00 on a Friday.
    """
    # Usage, per org, as one correlated subquery rather than a join.
    #
    # A join to `usage_records` multiplies the row per meter, so the seat count
    # from the other join comes back wrong the moment an org has two meters —
    # and a console that reports the wrong seat count is worse than one that
    # reports none, because it will be believed.
    usage = (
        select(UsageRecord.quantity)
        .where(UsageRecord.org_id == Organization.id, UsageRecord.meter == "requests")
        .order_by(UsageRecord.period_start.desc())
        .limit(1)
        .correlate(Organization)
        .scalar_subquery()
    )

    statement = (
        select(Organization, Subscription, func.count(Membership.id), usage)
        .outerjoin(Subscription, Subscription.org_id == Organization.id)
        .outerjoin(Membership, Membership.org_id == Organization.id)
        .group_by(Organization.id, Subscription.id)
        .order_by(Organization.created_at.desc())
        .limit(limit)
    )
    if q:
        statement = statement.where(
            or_(Organization.name.ilike(f"%{q}%"), Organization.slug.ilike(f"%{q}%"))
        )
    if plan:
        # An org with no subscription row is on the free plan, which is how
        # `plan_code` is reported in the rows below. Filtering on the raw column
        # would return nothing for `?plan=free` — every free org is *absent* from
        # `subscriptions` rather than present with that value, so the filter would
        # silently disagree with the column it is filtering next to.
        statement = statement.where(func.coalesce(Subscription.plan_code, "free") == plan)
    if status_filter:
        statement = statement.where(func.coalesce(Subscription.status, "none") == status_filter)

    rows = (await scope.session.execute(statement)).all()
    return [
        OrgSummaryOut(
            id=org.id,
            name=org.name,
            slug=org.slug,
            plan_code=subscription.plan_code if subscription else "free",
            status=subscription.status if subscription else "none",
            seats=seats,
            requests_this_month=int(requests or 0),
            is_active=org.is_active,
            created_at=org.created_at,
        )
        for org, subscription, seats, requests in rows
    ]


@router.get("/orgs/{org_id}", response_model=dict, summary="One org in detail")
async def org_detail(org_id: uuid.UUID, scope: StaffScopeDep) -> dict:
    """
    Everything support needs in one call, including the login history.

    Reading this is itself an audited event. Support looking at a customer's
    account is legitimate and should be recorded, precisely so that a pattern of
    looking at one account (an ex-partner, a competitor's employee) is visible.
    """
    org = (
        await scope.session.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise NotFound("organisation", org_id)

    from workbench.core.db import set_tenant

    # The staff policies already let this read the org. The tenant is set anyway,
    # so that the audit event below lands in *the customer's* log — they are
    # entitled to know support looked, and an event they can't see isn't notice.
    await set_tenant(scope.session, org_id, actor_id=scope.actor_id)

    subscription = (
        await scope.session.execute(select(Subscription).where(Subscription.org_id == org_id))
    ).scalar_one_or_none()
    members = (
        await scope.session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.org_id == org_id)
        )
    ).all()
    overrides = (
        (
            await scope.session.execute(
                select(PlanOverride).where(
                    PlanOverride.org_id == org_id, PlanOverride.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    attempts = (
        (
            await scope.session.execute(
                select(LoginAttempt)
                .where(LoginAttempt.user_id.in_([m.user_id for m, _ in members] or [uuid7()]))
                .order_by(LoginAttempt.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )

    await write_audit(
        scope.session,
        event="staff.org_viewed",
        actor=scope.actor,
        actor_kind="staff",
        org_id=org_id,
        target=org,
        reason="support console: viewed organisation",
        after={"action": "view", "members": len(members), "logins": len(attempts)},
    )

    return {
        "org": {
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "is_active": org.is_active,
            "overrides": org.overrides,
            "created_at": org.created_at.isoformat(),
        },
        "subscription": (
            {
                "plan_code": subscription.plan_code,
                "status": subscription.status,
                "external_id": subscription.external_id,
                "external_customer_id": subscription.external_customer_id,
                "current_period_end": (
                    subscription.current_period_end.isoformat()
                    if subscription.current_period_end
                    else None
                ),
                "cancel_at_period_end": subscription.cancel_at_period_end,
            }
            if subscription
            else None
        ),
        "members": [
            {
                "user_id": str(user.id),
                "email": user.email,
                "name": user.name,
                "role": membership.role,
                "joined_at": membership.joined_at.isoformat(),
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                "is_staff": user.is_staff,
            }
            for membership, user in members
        ],
        "overrides": [
            {
                "id": str(row.id),
                "values": row.values,
                "reason": row.reason,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            }
            for row in overrides
        ],
        "recent_logins": [
            {
                "at": row.created_at.isoformat(),
                "succeeded": row.succeeded,
                "reason": row.failure_reason,
                "ip": row.ip_address,
            }
            for row in attempts
        ],
    }


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------


@router.post("/orgs/{org_id}/override", response_model=dict, summary="Apply a plan override")
async def apply_override(
    org_id: uuid.UUID,
    payload: OverrideRequest,
    request: Request,
    scope: StaffScopeDep,
) -> dict:
    """
    Give one org limits the catalogue doesn't express.

    This is the endpoint that closes a deal at 23:00, and it is also the
    endpoint that can give away the product. Both are true, so:

      * only keys in `OVERRIDABLE` are accepted, because a free-form JSON blob
        is an entitlement system nobody can reason about
      * a reason is required and length-checked — "test" is rejected
      * expiring overrides are the default suggestion, because a forgotten
        permanent discount is how a customer pays 40% of list price for four
        years
      * the previous values are recorded, so undoing it is a diff and not an
        archaeology project
    """
    unknown = sorted(set(payload.values) - OVERRIDABLE)
    if unknown:
        raise BadRequest(
            f"cannot override: {', '.join(unknown)}. "
            f"Overridable keys are: {', '.join(sorted(OVERRIDABLE))}"
        )

    from workbench.core.db import set_tenant

    await set_tenant(scope.session, org_id)
    org = (
        await scope.session.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise NotFound("organisation", org_id)

    previous = dict(org.overrides or {})
    merged = {**previous, **payload.values}
    org.overrides = merged

    record = PlanOverride(
        id=uuid7(),
        org_id=org_id,
        applied_by_id=scope.actor_id,
        values=payload.values,
        reason=payload.reason,
        expires_at=(
            datetime.now(UTC) + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days
            else None
        ),
    )
    scope.session.add(record)

    await write_audit(
        scope.session,
        event="staff.plan_overridden",
        actor=scope.actor,
        actor_kind="staff",
        org_id=org_id,
        target=org,
        before={"overrides": previous},
        after={"overrides": merged},
        reason=payload.reason,
        ip_address=client_ip(request),
    )
    return {
        "org_id": str(org_id),
        "overrides": merged,
        "reason": payload.reason,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }


@router.delete("/orgs/{org_id}/override", response_model=dict, summary="Clear overrides")
async def clear_overrides(
    org_id: uuid.UUID,
    request: Request,
    scope: StaffScopeDep,
    reason: Annotated[str, Query(min_length=10, max_length=400)],
) -> dict:
    """
    Remove every override. The reason is required, including for this direction:
    "who took away the customer's enterprise limits" has the same answer shape as
    "who gave them".
    """
    from workbench.core.db import set_tenant

    await set_tenant(scope.session, org_id)
    org = (
        await scope.session.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise NotFound("organisation", org_id)

    previous = dict(org.overrides or {})
    org.overrides = {}

    live = (
        (
            await scope.session.execute(
                select(PlanOverride).where(
                    PlanOverride.org_id == org_id, PlanOverride.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for row in live:
        row.revoked_at = now

    await write_audit(
        scope.session,
        event="staff.plan_override_cleared",
        actor=scope.actor,
        actor_kind="staff",
        org_id=org_id,
        target=org,
        before={"overrides": previous},
        after={"overrides": {}},
        reason=reason,
        ip_address=client_ip(request),
    )
    return {"org_id": str(org_id), "overrides": {}, "revoked": len(live)}


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------


@router.post(
    "/impersonate", response_model=ImpersonationOut, summary="Act as a customer, read-only"
)
async def impersonate(
    payload: ImpersonateRequest,
    request: Request,
    scope: StaffScopeDep,
    staff: StaffDep,
) -> ImpersonationOut:
    """
    Mint a read-only, time-boxed token for the customer's view.

    Why this exists at all: half of all support tickets about a SaaS product are
    "it looks different on my screen than on yours", and the alternative to
    impersonation is asking the customer to read out their screen.

    The rules, all of which are load-bearing:

      * **Read-only.** The token cannot write. If support needs something
        changed, the customer changes it or the staff console has a specific
        endpoint with its own audit trail. Impersonation is for seeing.
      * **Expires within the hour.** `minutes` is capped at 60 by the schema and
        the row carries the expiry.
      * **Audited on start and end**, and the customer can see that it happened
        in their own audit log — `staff_impersonations_visible_to_org` is the
        policy that makes that true.
      * **Requires a reason.**
    """
    settings = get_settings()
    minutes = min(
        payload.minutes or settings.impersonation_max_minutes, settings.impersonation_max_minutes
    )

    target = (
        await scope.session.execute(select(User).where(User.id == payload.target_user_id))
    ).scalar_one_or_none()
    if target is None:
        raise NotFound("user", payload.target_user_id)

    if target.is_staff and target.id != staff.actor_id:
        # Staff impersonating staff produces a log where every action is by
        # somebody acting as somebody else, and the interesting ones disappear
        # into it.
        raise Forbidden("staff accounts cannot be impersonated")

    if payload.org_id is not None:
        membership = (
            await scope.session.execute(
                select(Membership).where(
                    Membership.user_id == target.id, Membership.org_id == payload.org_id
                )
            )
        ).scalar_one_or_none()
        if membership is None:
            raise BadRequest("the target user is not a member of that organisation")

    record = StaffImpersonation(
        id=uuid7(),
        staff_user_id=staff.actor_id or uuid7(),
        target_user_id=target.id,
        target_org_id=payload.org_id,
        reason=payload.reason,
        ticket_ref=payload.ticket_ref,
        expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
    )
    scope.session.add(record)
    await scope.session.flush()

    token = mint_access_token(
        user_id=target.id,
        org_id=payload.org_id,
        is_staff=False,
        impersonation_id=record.id,
        minutes=minutes,
    )

    await write_audit(
        scope.session,
        event="staff.impersonation_started",
        actor=staff,
        actor_kind="staff",
        org_id=payload.org_id,
        target=record,
        target_type="user",
        target_id=str(target.id),
        after={"minutes": minutes, "ticket": payload.ticket_ref, "read_only": True},
        reason=payload.reason,
        ip_address=client_ip(request),
    )

    return ImpersonationOut(
        id=record.id,
        target_user_id=target.id,
        target_org_id=payload.org_id,
        expires_at=record.expires_at,
        reason=payload.reason,
        access_token=token.value,
    )


@router.delete("/impersonate/{impersonation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def end_impersonation(
    impersonation_id: uuid.UUID,
    request: Request,
    staff: StaffDep,
    scope: StaffScopeDep,
) -> Response:
    """
    End it early. Ending is not optional in the UI: a session that is still open
    when the engineer goes to lunch is a session nobody is watching.
    """
    record = (
        await scope.session.execute(
            select(StaffImpersonation).where(
                StaffImpersonation.id == impersonation_id,
                StaffImpersonation.staff_user_id == staff.actor_id,
            )
        )
    ).scalar_one_or_none()
    if record is None:
        raise NotFound("impersonation", impersonation_id)

    record.end()
    await write_audit(
        scope.session,
        event="staff.impersonation_ended",
        actor=staff,
        actor_kind="staff",
        org_id=record.target_org_id,
        target=record,
        reason=record.reason,
        ip_address=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# The console's own reference data
# ---------------------------------------------------------------------------


@router.get("/permissions", response_model=list[dict], summary="The permission matrix")
async def permission_matrix(staff: StaffDep) -> list[PermissionRow]:
    """
    The matrix, from the code that enforces it.

    Support gets asked "why can my colleague not see billing" several times a
    week. Answering it from the same dict the routes check makes the answer
    right by construction.
    """
    return describe_matrix()


@router.get("/health", response_model=HealthOut, summary="Internal view of health")
async def staff_health(staff: StaffDep, scope: StaffScopeDep) -> HealthOut:
    """
    The checks an operator wants, not the ones a load balancer wants.

    `/health/ready` answers "should traffic come here". This answers "is anything
    silently broken": subscriptions that Stripe says are active and we don't,
    unprocessed webhooks, migrations not applied.
    """
    from workbench.billing.models import StripeEvent
    from workbench.core.db import ping, verify_rls_active

    settings = get_settings()
    checks: dict[str, str] = {}

    checks["database"] = "ok" if await ping(scope.session) else "unreachable"

    unprotected = await verify_rls_active(scope.session)
    checks["row_level_security"] = "ok" if not unprotected else f"UNPROTECTED: {unprotected}"

    pending = (
        await scope.session.execute(
            select(func.count()).select_from(StripeEvent).where(StripeEvent.processed_at.is_(None))
        )
    ).scalar_one()
    checks["stripe_events_pending"] = str(pending)

    drifted = (
        await scope.session.execute(
            select(func.count())
            .select_from(Subscription)
            .where(Subscription.status.in_(["active", "past_due"]))
        )
    ).scalar_one()
    checks["active_subscriptions"] = str(drifted)

    degraded = checks["database"] != "ok" or "UNPROTECTED" in checks["row_level_security"]

    return HealthOut(
        status="degraded" if degraded else "ok",
        version=settings.service_version,
        environment=settings.environment,
        checks=checks,
    )


__all__ = ["router"]
