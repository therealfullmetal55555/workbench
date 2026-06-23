"""
Processing a Stripe webhook.

This module joins the pure state machine in `state_machine.py` to a database, and
the order of its steps is the design:

    1. **Insert the event id. If it's already there, stop.** The uniqueness of
       `stripe_events.event_id` is the lock. Not a `SELECT` followed by an
       `INSERT` — that races with itself and Stripe delivers concurrently. Not a
       Redis key — that's a cache, and the thing must survive a restart, because
       the retry it protects against arrives after one.
    2. **Resolve the org.** From `client_reference_id`, then metadata, then the
       customer id, then the subscription id. Each of those is a policy-scoped
       read: the app role cannot see an organisation it wasn't handed.
    3. **Fold the event in** with `apply_event`, which is pure and tested.
    4. **Persist, mark processed, audit.** One transaction, so a crash halfway
       leaves the event unprocessed and the retry re-runs it — against a state
       that never saw the first half.

The order matters most at step 1 and 4. Recording the event *after* doing the
work is the version that emails a customer about an upgrade twice, and the bug
only appears under retry, which is to say under load.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from workbench.audit.log import write_audit
from workbench.billing.models import StripeEvent, Subscription
from workbench.billing.state_machine import (
    Event,
    Outcome,
    SubscriptionState,
    apply_event,
)
from workbench.core.db import (
    BILLING_CUSTOMER_SETTING,
    BILLING_SUBSCRIPTION_SETTING,
    set_credential,
    set_tenant,
)
from workbench.core.models import uuid7
from workbench.core.settings import get_settings
from workbench.email.sender import enqueue

log = logging.getLogger(__name__)


@dataclass(slots=True)
class HandleResult:
    status: str  # "applied" | "duplicate" | "ignored" | "deferred" | "failed"
    outcome: Outcome | None = None
    org_id: uuid.UUID | None = None
    detail: str | None = None
    retry: bool = False

    @property
    def http_status(self) -> int:
        """
        What to return to Stripe.

        200 for anything we have decided about, including events we don't handle —
        a 4xx tells Stripe to stop retrying and eventually disables the endpoint,
        and "we don't handle invoice.upcoming" is not a reason to stop receiving
        everything else. A retryable failure is a 500, and only a retryable one:
        Stripe's backoff over three days is a fine recovery mechanism, and an
        endpoint that returns 500 for a malformed event just gets disabled.
        """
        if self.status in {"applied", "duplicate", "ignored"}:
            return 200
        if self.status == "deferred":
            return 200
        return 500 if self.retry else 200


async def handle_webhook(
    session: AsyncSession,
    payload: dict[str, Any],
    *,
    hydrate: bool = True,
) -> HandleResult:
    """
    Process one verified webhook body.

    The caller has already checked the signature — this function is reachable
    only from `POST /webhooks/stripe` after `verify_signature` returned, and it
    is written assuming an attacker cannot reach it. If that assumption ever
    changes, the resolution steps below become an oracle for enumerating
    customers.
    """
    event = Event.from_payload(payload)
    if not event.id:
        return HandleResult("ignored", detail="event has no id")

    settings = get_settings()

    # -- 1. the idempotency ledger ---------------------------------------
    claimed = await _claim_event(session, event)
    if claimed is None:
        log.info("duplicate webhook", extra={"event_id": event.id, "type": event.type})
        return HandleResult("duplicate", detail="already processed")

    # -- 2. resolve the org ----------------------------------------------
    org_id = await _resolve_org(session, event)
    record = claimed

    if (
        event.type == "checkout.session.completed"
        and hydrate
        and not event.data.get("subscription_object")
    ):
        hydrated = await _hydrate(session, event, record)
        if hydrated is not None:
            payload = hydrated

    if org_id is None and not event.data.get("subscription_object"):
        # Nothing ties this event to an org yet. Not an error: Stripe will send
        # `customer.subscription.created` for the same subscription, and that one
        # carries the customer. Marked processed so the retry of *this* event
        # doesn't loop; the ledger row keeps the payload for diagnosis.
        log.warning(
            "webhook with no resolvable organisation",
            extra={"event_id": event.id, "type": event.type},
        )
        await _finish(session, record, org_id=None, error=None)
        return HandleResult("deferred", detail="org not resolvable yet")

    subscription_id = str(event.data.get("id") or event.data.get("subscription") or "")

    # The tenant is bound before the row is looked up, not after it is found.
    #
    # The order reads naturally the other way — find the subscription, learn the
    # org from it, then bind — and it is wrong for the half of the lookup that
    # goes by org: `subscriptions` is scoped by `app.current_org`, so an
    # org-scoped read issued before the setting lands returns nothing, `_persist`
    # concludes this is a brand-new subscription, and the insert collides with
    # the one-subscription-per-org index. Postgres reports a unique violation
    # during an upgrade, which is a thoroughly misleading way to describe a
    # missing `set_config`.
    #
    # The external-id lookup needs no tenant (that is what the
    # `subscriptions_by_external_id` policy is for), so the binding is
    # conditional and the fallback below stays possible.
    if org_id is not None:
        await set_tenant(session, org_id)

    state_row = await _load_state(session, org_id=org_id, external_id=subscription_id)

    if state_row is not None and org_id is None:
        org_id = state_row.org_id
        await set_tenant(session, org_id)

    if org_id is None:
        await _finish(session, record, org_id=None, error=None)
        return HandleResult("deferred", detail="no org for this subscription")

    state = _state_of(state_row)
    new_state, outcome = apply_event(
        state, Event.from_payload(payload), price_map=settings.stripe_price_ids
    )

    if outcome == "unhandled":
        # Recognised as an event, not as one that changes anything. Logged at
        # info rather than warned: an unhandled event type is not a problem, and
        # a warning per delivery trains people to ignore warnings.
        await _finish(session, record, org_id=org_id, error=None)
        return HandleResult("ignored", outcome=outcome, org_id=org_id)

    if outcome in {"stale", "other_object"}:
        log.info(
            "webhook folded with no change",
            extra={"event_id": event.id, "type": event.type, "outcome": outcome},
        )
        await _finish(session, record, org_id=org_id, error=None)
        return HandleResult(outcome, outcome=outcome, org_id=org_id)

    # `applied`, or `noop` with a newer ordering timestamp to record. Persisting
    # an unchanged state costs one UPDATE and keeps `last_event_at` honest, which
    # is what decides staleness for everything that arrives after it.
    await _persist(
        session, org_id=org_id, row=state_row, state=new_state, event=event, outcome=outcome
    )
    await _finish(session, record, org_id=org_id, error=None)

    return HandleResult(outcome, outcome=outcome, org_id=org_id)


async def _claim_event(session: AsyncSession, event: Event) -> StripeEvent | None:
    """
    Claim the event id, or return None if someone already has.

    `ON CONFLICT DO NOTHING ... RETURNING id` makes this one statement and one
    round trip, and returns nothing when the row existed. The same thing written
    as `SELECT` then `INSERT` has a window between them exactly as wide as Stripe's
    concurrent delivery of the same event.

    `stripe_events` is the one table with no tenant policy — see the migration for
    why — so this works before an org is known, which is the whole requirement.
    """
    statement = (
        pg_insert(StripeEvent)
        .values(
            id=uuid7(),
            event_id=event.id,
            event_type=event.type,
            org_id=None,
            payload=event.data,
            attempts=0,
        )
        .on_conflict_do_nothing(index_elements=["event_id"])
        .returning(StripeEvent.id)
    )
    inserted = (await session.execute(statement)).scalar_one_or_none()
    if inserted is None:
        return None

    return (
        await session.execute(select(StripeEvent).where(StripeEvent.id == inserted))
    ).scalar_one()


async def _finish(
    session: AsyncSession, record: StripeEvent, *, org_id: uuid.UUID | None, error: str | None
) -> None:
    record.processed_at = datetime.now(UTC)
    record.org_id = org_id
    record.last_error = error
    record.attempts = record.attempts + (1 if error else 0)
    await session.flush()


async def _resolve_org(session: AsyncSession, event: Event) -> uuid.UUID | None:
    """
    Four ways to find the organisation, cheapest and most reliable first.

      1. `client_reference_id` / metadata — we put it there; nothing to look up
      2. the customer id, via the `organizations_billing_lookup` policy
      3. the subscription id, via the `subscriptions_by_external_id` policy
      4. nothing — the caller defers

    Steps 2 and 3 are the ones that need the GUCs. They exist because a webhook
    has no session and no user: the signature is the credential, and the id it
    names is what it is allowed to look up.
    """
    if event.org_id:
        try:
            return uuid.UUID(str(event.org_id))
        except (ValueError, TypeError):
            log.warning("webhook org id is not a uuid", extra={"value": event.org_id})

    customer_id = event.data.get("customer")
    if customer_id:
        await set_credential(session, BILLING_CUSTOMER_SETTING, str(customer_id))
        from workbench.tenancy.models import Organization

        found = (
            await session.execute(
                select(Organization.id).where(Organization.billing_customer_id == str(customer_id))
            )
        ).scalar_one_or_none()
        if found is not None:
            return found

    subscription_id = event.data.get("id") or event.data.get("subscription")
    if subscription_id:
        await set_credential(session, BILLING_SUBSCRIPTION_SETTING, str(subscription_id))

        # Read the org id *from the subscription*, then load the org under its own
        # tenant — two steps rather than one join, and the join is the version
        # that does not work.
        #
        # `subscriptions_by_external_id` lets the credential named in the setting
        # see one subscription row: that is the whole permission. Joining it to
        # `organizations` asks for the organisation too, and `organizations` has
        # no policy keyed on a subscription id — only on the customer, the
        # tenant, or staff. So the join filtered the org away and every
        # subscription-only event (an invoice, most importantly) resolved to no
        # org at all. Those events are then deferred and marked processed, which
        # means no error, no retry, and a payment failure that never reaches the
        # billing state: precisely the class of silent failure this module is
        # supposed to be protected from.
        org_id_here = (
            await session.execute(
                select(Subscription.org_id).where(Subscription.external_id == str(subscription_id))
            )
        ).scalar_one_or_none()
        if org_id_here is not None:
            return org_id_here

    return None


async def _load_state(
    session: AsyncSession, *, org_id: uuid.UUID | None, external_id: str
) -> Subscription | None:
    """
    The subscription row, if there is one.

    Looked up by org when known, by external id otherwise. Both are policy-scoped:
    the second read is why `subscriptions_by_external_id` exists, and it is
    limited to exactly the subscription the event names.
    """
    if org_id is not None:
        await set_credential(session, BILLING_SUBSCRIPTION_SETTING, external_id or "-")
        return (
            await session.execute(select(Subscription).where(Subscription.org_id == org_id))
        ).scalar_one_or_none()

    if external_id:
        return (
            await session.execute(
                select(Subscription).where(Subscription.external_id == external_id)
            )
        ).scalar_one_or_none()
    return None


def _state_of(row: Subscription | None) -> SubscriptionState:
    if row is None:
        return SubscriptionState()
    return SubscriptionState(
        plan_code=row.plan_code,
        status=row.status,
        external_id=row.external_id,
        external_customer_id=row.external_customer_id,
        external_price_id=row.external_price_id,
        quantity=row.quantity,
        current_period_start=row.current_period_start,
        current_period_end=row.current_period_end,
        cancel_at_period_end=row.cancel_at_period_end,
        canceled_at=row.canceled_at,
        trial_ends_at=row.trial_ends_at,
        # The ordering clock and the id of the event that set it. Omitting these
        # two reads makes every event look like the newest news: `last_event_at`
        # comes back None, so the staleness check in `apply_event` never fires,
        # and a queued redelivery of last week's cancellation lands on top of a
        # subscription that was upgraded this morning. The row was being written
        # correctly and read back without the two fields that give it meaning.
        last_event_at=row.last_event_at,
        last_event_id=row.last_event_id,
        raw=row.raw or {},
    )


async def _persist(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    row: Subscription | None,
    state: SubscriptionState,
    event: Event,
    outcome: Outcome,
) -> None:
    """
    Write the new state, and audit the change.

    The audit event is written for every transition, including the ones that look
    boring. "Why did this customer's plan change on the 14th" is answered here or
    it is answered by reading Stripe's dashboard and guessing.
    """
    before_plan = row.plan_code if row else "free"
    before_status = row.status if row else "none"

    if row is None:
        row = Subscription(id=uuid7(), org_id=org_id)
        session.add(row)

    for key, value in state.to_subscription_kwargs().items():
        if key not in Subscription.__table__.columns:
            # `setattr` on an unmapped attribute is not an error: SQLAlchemy
            # happily stores it on the instance and nothing reaches the database.
            # That is how `last_event_at` spent a week being written into a void
            # while the ordering logic read `None` and called every event fresh.
            # The check is cheap and it fails at the first webhook after a
            # schema mistake instead of at the first customer complaint.
            raise RuntimeError(
                f"SubscriptionState.{key} has no column on subscriptions — "
                "the state machine would write it into the instance and lose it"
            )
        setattr(row, key, value)

    await session.flush()

    if before_plan != state.plan_code:
        event_kind = (
            "billing.subscription_created" if before_status == "none" else "billing.plan_changed"
        )
        await write_audit(
            session,
            event=event_kind,
            org_id=org_id,
            actor_kind="webhook",
            target=row,
            before={"plan_code": before_plan},
            after={"plan_code": state.plan_code, "status": state.status},
        )

    if before_status != state.status:
        if state.status == "past_due":
            await write_audit(
                session,
                event="billing.payment_failed",
                org_id=org_id,
                actor_kind="webhook",
                target=row,
                after={"status": state.status, "event_id": event.id},
            )
            await _notify_payment_failed(session, org_id, row)
        elif state.status == "active":
            await write_audit(
                session,
                event="billing.payment_succeeded",
                org_id=org_id,
                actor_kind="webhook",
                target=row,
                after={"status": state.status, "event_id": event.id},
            )
        elif state.status == "canceled":
            await write_audit(
                session,
                event="billing.subscription_canceled",
                org_id=org_id,
                actor_kind="webhook",
                target=row,
                after={"status": state.status, "event_id": event.id},
            )


# ---------------------------------------------------------------------------
# Emails, which are the only place the state machine reaches a human
# ---------------------------------------------------------------------------


# There is deliberately no "your plan changed" email. Stripe sends the receipt
# and the invoice within seconds, the customer is the one who clicked the button,
# and a third message saying "you changed your plan" is the kind of copy people
# filter by sender. The change is in the audit log and on the billing screen,
# which is where somebody looks a month later when they wonder why the invoice
# was different.


async def _notify_payment_failed(
    session: AsyncSession, org_id: uuid.UUID, row: Subscription
) -> None:
    """
    The dunning email, and the first row of the dunning ladder.

    Sent on the transition into `past_due` only — not on every failed invoice
    event, because the state machine drops the repeats. A customer who gets four
    copies of the same message about one declined card calls support angry.
    """
    from workbench.billing.models import DunningAttempt

    recipient = await _billing_contact(session, org_id)
    if not recipient:
        return

    settings = get_settings()
    attempts = (
        (await session.execute(select(DunningAttempt).where(DunningAttempt.org_id == org_id)))
        .scalars()
        .all()
    )
    step = len(attempts) + 1

    session.add(
        DunningAttempt(
            id=uuid7(),
            org_id=org_id,
            subscription_id=row.id,
            step=step,
            template="payment_failed",
        )
    )
    await session.flush()

    enqueue(
        "payment_failed",
        to=recipient,
        org_name=await _org_name(session, org_id),
        amount="your last invoice",
        plan_name=row.plan_code.title(),
        update_url=f"{get_settings().app_base_url}/billing",
        attempt=step,
        max_attempts=settings.webhook_max_attempts,
        next_attempt_at="in three days",
        read_only_at="two weeks from now",
    )


async def _billing_contact(session: AsyncSession, org_id: uuid.UUID) -> str | None:
    """
    Who to email about money.

    The owner, always — not every admin. A payment email to five people is a
    payment email nobody acts on, and it puts an invoice amount in front of
    people who have no reason to see one.
    """
    from sqlalchemy import func

    from workbench.auth.models import User
    from workbench.tenancy.models import Membership

    return (
        await session.execute(
            select(User.email)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.org_id == org_id, Membership.role == "owner")
            .order_by(func.coalesce(User.last_login_at, User.created_at).desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _org_name(session: AsyncSession, org_id: uuid.UUID) -> str:
    from workbench.tenancy.models import Organization

    return (
        await session.execute(select(Organization.name).where(Organization.id == org_id))
    ).scalar_one_or_none() or "your organisation"


async def _hydrate(
    session: AsyncSession, event: Event, record: StripeEvent
) -> dict[str, Any] | None:
    """
    Fill in a checkout session's subscription before folding it.

    Best-effort on purpose. If Stripe's API is unreachable, the event is still
    processed with what it has — the customer association — and the
    `customer.subscription.created` that follows does the real work. Blocking
    here would make the webhook depend on a second Stripe call succeeding within
    Stripe's own timeout, which is how a webhook endpoint gets disabled.
    """
    subscription_id = event.data.get("subscription")
    if not subscription_id:
        return None

    from workbench.billing.stripe_gateway import StripeError, get_gateway

    try:
        subscription = await get_gateway().fetch_subscription(str(subscription_id))
    except StripeError as exc:
        record.last_error = str(exc)[:1000]
        record.attempts += 1
        log.warning("could not hydrate checkout session", extra={"event_id": event.id})
        return None

    # Returned in the same shape the state machine reads from the raw body, with
    # the subscription spliced in — so `_checkout` can fold a hydrated session
    # and a plain `customer.subscription.created` with one code path.
    return {
        "id": event.id,
        "type": event.type,
        "created": int(event.created.timestamp()),
        "data": {
            "object": {
                **event.data,
                "subscription_object": dict(subscription),
            }
        },
    }


__all__ = ["HandleResult", "handle_webhook"]
