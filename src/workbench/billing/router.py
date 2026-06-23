"""
Billing endpoints, plus the webhook.

The webhook lives in this file rather than in its own module because it is the
same subject matter and because it is the one endpoint in the service with no
authentication — putting it next to the authenticated ones keeps the difference
visible. It reads the raw body, verifies a signature, and never touches a
session belonging to a user.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy import select

from workbench.api.deps import Scope, SystemDep, requires
from workbench.api.errors import BadRequest, Conflict, ServiceUnavailable
from workbench.api.schemas import CheckoutRequest, EntitlementsOut, PlanOut, PortalRequest
from workbench.audit.log import write_audit
from workbench.billing.entitlements import all_plans
from workbench.billing.models import Subscription
from workbench.billing.stripe_gateway import (
    BillingNotConfigured,
    SignatureError,
    StripeError,
    StripeGateway,
    get_gateway,
    verify_signature,
)
from workbench.billing.webhooks import handle_webhook
from workbench.core.settings import Settings, get_settings

log = logging.getLogger(__name__)

router = APIRouter(tags=["billing"])


def gateway() -> StripeGateway:
    """Overridden in tests with a fake; one call site so the seam is explicit."""
    return get_gateway()


GatewayDep = Annotated[StripeGateway, Depends(gateway)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


# ---------------------------------------------------------------------------
# What the customer may do
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/entitlements", response_model=EntitlementsOut)
async def read_entitlements(
    scope: Annotated[Scope, Depends(requires("billing:read"))],
) -> EntitlementsOut:
    """
    Everything the billing screen needs, resolved in one call.

    The org's *effective* limits, not the plan's: an override and a mid-period
    downgrade both mean the catalogue's numbers would be wrong, and a customer
    comparing their screen against the pricing page is a support ticket.
    """
    assert scope.entitlements is not None
    return EntitlementsOut.model_validate(scope.entitlements.to_dict())


@router.get("/plans", response_model=list[PlanOut], summary="Public plan catalogue")
async def list_plans() -> list[PlanOut]:
    """
    Public, and unauthenticated on purpose.

    The pricing page renders from this, which means the numbers on it come from
    the code that enforces them. The alternative — a pricing page maintained by
    hand — is a page that disagrees with the product within a quarter.
    """
    return [PlanOut.model_validate(plan) for plan in all_plans()]


@router.post("/billing/checkout", response_model=dict)
async def create_checkout(
    payload: CheckoutRequest,
    request: Request,
    scope: Annotated[Scope, Depends(requires("billing:write", write=True))],
    gw: GatewayDep,
    settings: SettingsDep,
) -> dict:
    """
    Start an upgrade, or a first subscription for a free org.

    The Stripe customer is created lazily — at the moment money is involved, not
    at signup. A signup that calls Stripe is a signup that fails when Stripe is
    slow, for a customer who was never going to pay today.
    """
    org = scope.org
    assert org is not None

    # None on a first upgrade. Stripe's Checkout creates the customer itself when
    # it is given an email and no customer id, and the id comes back on the
    # webhook. Creating it here would be a second API call and a second failure
    # mode on the one screen where a customer is trying to give us money.
    customer_id = org.billing_customer_id

    try:
        session = await gw.create_checkout_session(
            org_id=str(org.id),
            plan_code=payload.plan_code,
            customer_id=customer_id,
            customer_email=scope.actor_email,
            success_url=payload.success_url or f"{settings.app_base_url}/billing?upgraded=1",
            cancel_url=payload.cancel_url or f"{settings.app_base_url}/billing",
        )
    except BillingNotConfigured as exc:
        raise ServiceUnavailable(str(exc)) from exc
    except StripeError as exc:
        raise Conflict(str(exc)) from exc

    await write_audit(
        scope.session,
        event="billing.plan_changed",
        actor=scope.actor,
        org_id=org.id,
        target=org,
        after={"checkout_started": payload.plan_code, "session": session.id},
        ip_address=request.client.host if request.client else None,
    )
    # 200 with a URL rather than a 302: the client decides whether to navigate
    # the current tab or open a new one, and an API that returns redirects is an
    # API that can't be called from a fetch().
    return {"checkout_url": session.url, "session_id": session.id}


@router.post("/billing/portal", response_model=dict)
async def open_portal(
    payload: PortalRequest,
    scope: Annotated[Scope, Depends(requires("billing:write"))],
    gw: GatewayDep,
    settings: SettingsDep,
) -> dict:
    """
    The Stripe-hosted portal: cards, invoices, cancellation, plan changes.

    Deliberately not gated on `write=True`. Opening the portal from a read-only
    org is exactly what a customer with a failed payment needs to do — refusing
    it turns "update your card" into a call to support.
    """
    org = scope.org
    assert org is not None
    if not org.billing_customer_id:
        raise BadRequest("this organisation has no billing account yet")

    try:
        session = await gw.create_portal_session(
            customer_id=org.billing_customer_id,
            return_url=payload.return_url or f"{settings.app_base_url}/billing",
        )
    except BillingNotConfigured as exc:
        raise ServiceUnavailable(str(exc)) from exc
    except StripeError as exc:
        raise Conflict(str(exc)) from exc

    return {"portal_url": session.url}


@router.post(
    "/orgs/{org_id}/billing/cancel",
    response_model=dict,
    summary="Cancel at the end of the period",
)
async def cancel_subscription(
    request: Request,
    scope: Annotated[Scope, Depends(requires("billing:write", write=True))],
    gw: GatewayDep,
) -> dict:
    """
    Cancel at period end, not immediately.

    The customer paid for this month. Turning the product off on the day they
    click the button produces a refund request and a one-star review, and the
    month they already paid for costs nothing to honour.

    The local state is *not* updated here. The webhook does that, so there is one
    writer for subscription state and the two can't disagree.
    """
    subscription = (
        await scope.session.execute(select(Subscription).where(Subscription.org_id == scope.org_id))
    ).scalar_one_or_none()

    if subscription is None or not subscription.external_id:
        raise BadRequest("this organisation has no active subscription to cancel")

    try:
        await gw.cancel_subscription(subscription.external_id, at_period_end=True)
    except BillingNotConfigured as exc:
        raise ServiceUnavailable(str(exc)) from exc
    except StripeError as exc:
        raise Conflict(str(exc)) from exc

    await write_audit(
        scope.session,
        event="billing.subscription_canceled",
        actor=scope.actor,
        org_id=scope.org_id,
        target=subscription,
        after={"cancel_at_period_end": True, "until": str(subscription.current_period_end)},
        reason="customer requested cancellation",
        ip_address=request.client.host if request.client else None,
    )
    return {
        "status": "scheduled",
        "access_until": subscription.current_period_end,
        "detail": "the subscription stays active until the end of the paid period",
    }


# ---------------------------------------------------------------------------
# The webhook
# ---------------------------------------------------------------------------


@router.post(
    "/webhooks/stripe",
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    summary="Stripe webhook receiver",
)
async def stripe_webhook(
    request: Request,
    scope: SystemDep,
    stripe_signature: Annotated[str | None, Header(alias="Stripe-Signature")] = None,
) -> dict:
    """
    Receive, verify, and process one Stripe event.

    Read the body as **bytes**, before any JSON parsing. The signature covers the
    exact bytes Stripe sent; parsing and re-serialising changes key order and
    whitespace, and the signature then fails for every event — which looks like
    an attack and is a bug in your own handler.

    The response codes are part of the contract. Stripe retries anything that
    isn't 2xx, with backoff, for up to three days, and then disables the endpoint
    and emails you. So: 200 for anything we have decided about, including events
    we don't handle; 400 only for a request that isn't from Stripe; 500 for the
    subset we want retried.
    """
    body = await request.body()
    settings = get_settings()

    try:
        verify_signature(body, stripe_signature, settings.stripe_webhook_secret)
    except BillingNotConfigured as exc:
        log.error("stripe webhook rejected: %s", exc)
        raise ServiceUnavailable("billing is not configured on this instance") from exc
    except SignatureError as exc:
        # 400, and logged at warning with the reason. A silent 400 here is a
        # support case that takes a day to diagnose; a loud one is five minutes.
        log.warning("stripe webhook signature rejected", extra={"reason": str(exc)})
        raise BadRequest(f"signature verification failed: {exc}") from exc

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise BadRequest("body is not valid JSON") from exc

    result = await handle_webhook(scope.session, payload)

    if result.http_status >= 400:
        # Raising inside the transaction rolls back the ledger insert, so the
        # retry can claim it again. Committing it and returning 500 would mark a
        # failed event as seen.
        raise ServiceUnavailable(
            "the event could not be processed and will be retried", event_id=payload.get("id")
        )

    return {
        "received": True,
        "status": result.status,
        "outcome": result.outcome,
        "org": str(result.org_id) if result.org_id else None,
    }


@router.get("/webhooks/stripe/health", include_in_schema=False)
async def webhook_health(scope: SystemDep) -> dict:
    """
    Recent deliveries, for the dashboard.

    The question this answers is "are we losing money because webhooks stopped",
    and it is answered by the count of unprocessed events rather than by an
    uptime check — an endpoint can return 200 cheerfully while every handler
    raises.
    """
    from sqlalchemy import func

    from workbench.billing.models import StripeEvent

    pending = (
        await scope.session.execute(
            select(func.count()).select_from(StripeEvent).where(StripeEvent.processed_at.is_(None))
        )
    ).scalar_one()
    failed = (
        await scope.session.execute(
            select(func.count()).select_from(StripeEvent).where(StripeEvent.attempts > 0)
        )
    ).scalar_one()

    return {"pending": pending, "with_errors": failed, "healthy": pending == 0}


__all__ = ["router"]
