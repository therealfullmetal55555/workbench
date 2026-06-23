"""
The subscription state machine, as a pure function.

This is the answer to "how do you handle webhooks arriving out of order", and the
answer is not a queue, a lock, or a `SELECT ... FOR UPDATE`. It is that the
transition is a function:

    apply_event(current_state, event) -> (new_state, outcome)

Given the same inputs it always produces the same output, so *any* interleaving
of deliveries converges on the same final state as long as they are all delivered.
Delivery order stops mattering, which is what you want: Stripe retries, batches
and occasionally delivers yesterday's event after today's, and it does not
promise ordering on your endpoint while doing it.

Three guards, in this order, and each one exists because of a specific bug:

1. **Unknown event types return `ignored`.** Adding a handler is a deploy; the
   webhook endpoint returning 500 because it doesn't recognise
   `invoice.upcoming` is how Stripe disables your endpoint after three days of
   failures.

2. **Identity before recency.** An event naming a *different* subscription than
   the one on file is ignored unless it is newer, because the natural flow is
   "cancel old, create new" and the cancel can arrive second. Applying it would
   cancel a freshly-upgraded customer — a support ticket that arrives within the
   hour and a churn risk that arrives within the month.

3. **Snapshots, not deltas, and the newest one wins.** Every Stripe subscription
   event carries the whole subscription, not a change to it. So an older event
   applied after a newer one is a regression, and the `event.created` timestamp is
   what tells them apart. No arithmetic means no drift.

The function is pure: no database, no clock, no network. Which is why the
ordering tests take microseconds instead of needing a Stripe account.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Literal

from workbench.billing.plans import CATALOGUE, get_plan, is_valid_plan

log = logging.getLogger(__name__)

Outcome = Literal[
    "applied",  # the state changed
    "noop",  # recognised, but nothing to change
    "stale",  # older than what is already applied
    "other_object",  # names a different subscription than the one on file
    "unhandled",  # an event type this version doesn't know
    "unresolved",  # no org could be attached to it
]

# Event types that change subscription state. Everything else (invoice.*,
# payment_intent.*, charge.*) is either derived from one of these or fetched
# fresh when it matters.
SUBSCRIPTION_EVENTS = frozenset(
    {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "customer.subscription.trial_will_end",
    }
)

# Events that carry a payment outcome rather than a subscription snapshot. They
# flip status between `active` and `past_due` and nothing else — because the
# invoice is a fact about a payment, not about what the customer bought.
PAYMENT_EVENTS = frozenset(
    {
        "invoice.payment_failed",
        "invoice.payment_succeeded",
        "invoice.paid",
    }
)

# `checkout.session.completed` is special: it is the only event that can attach
# a brand-new subscription to an org we have never heard of, and it carries the
# client_reference_id we set when creating the session.
CHECKOUT_EVENTS = frozenset(
    {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
    }
)

HANDLED = SUBSCRIPTION_EVENTS | PAYMENT_EVENTS | CHECKOUT_EVENTS

# Terminal statuses. Once a subscription is `canceled`, nothing that happens to
# that same subscription id brings it back — Stripe never resurrects one. This is
# what stops a replay of an old `updated` event from reviving a cancelled
# customer, which is otherwise indistinguishable from a legitimate update.
TERMINAL_STATUSES = frozenset({"canceled", "incomplete_expired"})


@dataclass(frozen=True, slots=True)
class SubscriptionState:
    """The subset of a subscription the state machine reads and writes."""

    plan_code: str = "free"
    status: str = "none"
    external_id: str | None = None
    external_customer_id: str | None = None
    external_price_id: str | None = None
    quantity: int = 1
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    canceled_at: datetime | None = None
    trial_ends_at: datetime | None = None
    # The `created` timestamp of the last event applied. This is the ordering
    # clock, and it is Stripe's, not ours — our receive time is the thing that
    # arrives out of order.
    last_event_at: datetime | None = None
    last_event_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_subscription_kwargs(self) -> dict[str, Any]:
        """Everything a `Subscription` row needs, minus the org id."""
        return {
            "plan_code": self.plan_code,
            "status": self.status,
            "external_id": self.external_id,
            "external_customer_id": self.external_customer_id,
            "external_price_id": self.external_price_id,
            "quantity": self.quantity,
            "current_period_start": self.current_period_start,
            "current_period_end": self.current_period_end,
            "cancel_at_period_end": self.cancel_at_period_end,
            "canceled_at": self.canceled_at,
            "trial_ends_at": self.trial_ends_at,
            # Part of the row, not bookkeeping. Leaving these two out of the
            # write is the other half of the same bug as leaving them out of the
            # read: the state machine computes the ordering clock on every event
            # and then dropped it on the floor, so every delivery was compared
            # against `None` and treated as the newest news.
            "last_event_at": self.last_event_at,
            "last_event_id": self.last_event_id,
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class Event:
    """What the state machine needs from a Stripe event, and no more."""

    id: str
    type: str
    created: datetime
    data: dict[str, Any]
    org_id: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Event:
        """Build from the raw webhook body. Tolerant: Stripe adds fields, never removes."""
        raw_created = payload.get("created")
        created = (
            datetime.fromtimestamp(int(raw_created), tz=UTC)
            if raw_created is not None
            else datetime.now(UTC)
        )
        data = payload.get("data", {}).get("object", {}) or {}
        return cls(
            id=str(payload.get("id", "")),
            type=str(payload.get("type", "")),
            created=created,
            data=data,
            org_id=(data.get("client_reference_id") or data.get("metadata", {}).get("org_id")),
        )


def _subject_id(event: Event) -> str | None:
    """
    The subscription an event is about.

    A `customer.subscription.*` event *is* the subscription, so its `id` is the
    one we want. An invoice is not: it names its subscription in a separate
    field, and that field moved. It used to be `object.subscription`; in recent
    versions it is `object.parent.subscription_details.subscription`, and for the
    first invoice of a subscription either can be absent.

    Reading only the old shape fails in the quietest possible way. The invoice
    event is folded as "no subscription id", which is logged at `info` next to
    every other unremarkable delivery — so payment failures stop moving an org to
    `past_due`, no error is raised anywhere, and the first sign of trouble is a
    customer whose card has been failing for a week and who has noticed nothing.
    """
    explicit = event.data.get("id")
    if event.type not in PAYMENT_EVENTS:
        return str(explicit) if explicit else None

    parent = event.data.get("parent") or {}
    details = (parent.get("subscription_details") or {}) if isinstance(parent, dict) else {}
    named = (
        event.data.get("subscription")
        or details.get("subscription")
        or (explicit if str(explicit or "").startswith("sub_") else None)
    )
    return str(named) if named else None


def apply_event(
    state: SubscriptionState, event: Event, *, price_map: dict[str, str] | None = None
) -> tuple[SubscriptionState, Outcome]:
    """
    Fold one event into the current state.

    `price_map` maps a Stripe price id to a plan code, from settings. Unknown
    price ids keep the current plan and log — see `_plan_for`.
    """
    if event.type not in HANDLED:
        return state, "unhandled"

    handler = {
        "checkout.session.completed": _checkout,
        "checkout.session.async_payment_succeeded": _checkout,
    }.get(event.type)

    if handler is not None:
        return handler(state, event, price_map or {})

    # Every remaining handler needs a subscription id and a timestamp. An event
    # without the id is malformed; without a timestamp, we cannot order it, so
    # treating it as stale is the safe direction — the alternative is applying
    # an unordered event over a known-newer state.
    external_id = _subject_id(event)
    if not external_id:
        log.warning("billing event without a subscription id", extra={"event": event.type})
        return state, "noop"

    if state.last_event_at is not None and event.created < state.last_event_at:
        # Same object, older news. This is the out-of-order case, and ignoring it
        # is the whole trick: the newer snapshot already reflects this state.
        return state, "stale"

    # A different subscription id is not automatically wrong.
    #
    # There used to be an identity guard here: an event naming another
    # subscription was folded away as `other_object`, on the reasoning that a
    # cancel for a subscription we had replaced must not cancel its successor.
    # That reasoning is right about the *stale* direction, which the check above
    # already handles — and it was wrong about the fresh one. On a plan change
    # Stripe cancels the old subscription and creates a new one, and nothing
    # guarantees the create is delivered second. Delivered first, the guard threw
    # the new subscription away, then the cancel of the old one landed on the row,
    # and the customer who had just upgraded was left cancelled.
    #
    # So the newest event wins, identity included: if Stripe says this org's
    # subscription is now a different object, the row follows it and takes the
    # new id. The cost is that an org with two live subscriptions keeps whichever
    # one Stripe last spoke about — a state this schema cannot represent anyway
    # (one row per org, by unique index), and one the audit trail records.

    if (
        state.external_id is not None
        and external_id != state.external_id
        and event.type != "customer.subscription.created"
    ):
        # News about a subscription that is no longer the one on file.
        #
        # A *create* for a different object is how an upgrade arrives: Stripe
        # issues a new subscription id, so a new object is exactly what the org's
        # row should become. Everything else about a superseded object is noise —
        # the cancellation that came with the upgrade, a redelivered `updated`,
        # the invoice for the subscription the customer just left — and applying
        # it means cancelling a customer who has already been moved onto the new
        # plan.
        #
        # Note what this compares. Not timestamps: an event about a *different*
        # object has its own timeline, and the cancellation of the old
        # subscription is routinely newer than the creation of the new one. What
        # decides is identity: either the event names the subscription on file, or
        # it introduces a new one. Nothing else moves this row.
        return state, "other_object"

    if state.is_terminal and state.external_id == external_id:
        # Cancelled is final for that subscription id. A late `updated` for it is
        # not a resurrection.
        return state, "noop"

    if event.type in PAYMENT_EVENTS:
        return _payment(state, event)

    if event.type == "customer.subscription.deleted":
        # Already guarded for staleness above, so reaching here means this is the
        # newest news about the subscription on file: it is genuinely cancelled.
        return (
            replace(
                state,
                status="canceled",
                canceled_at=event.created,
                cancel_at_period_end=False,
                last_event_at=event.created,
                last_event_id=event.id,
                raw=event.data,
            ),
            "applied",
        )

    if event.type == "customer.subscription.trial_will_end":
        # A courtesy notification, not a state change, and it arrives three days
        # *before* the trial ends. The state it describes is already on file from
        # the last `updated`. Deliberately not used to change anything: doing so
        # would be a write whose only effect is to make the row match what it
        # already says.
        return state, "noop"

    return _subscription(state, event, price_map or {})


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _subscription(
    state: SubscriptionState, event: Event, price_map: dict[str, str]
) -> tuple[SubscriptionState, Outcome]:
    """One of `customer.subscription.created` / `.updated`. Both are snapshots."""
    data = event.data
    status = _status(data)
    price_id = _price_id(data)

    updates: dict[str, Any] = {
        "external_id": str(data.get("id")),
        "external_customer_id": data.get("customer") or state.external_customer_id,
        "external_price_id": price_id or state.external_price_id,
        "status": status,
        "quantity": int(data.get("quantity") or 1),
        "cancel_at_period_end": bool(data.get("cancel_at_period_end", False)),
        "canceled_at": _timestamp(data.get("canceled_at")),
        "trial_ends_at": _timestamp(data.get("trial_end")),
        "current_period_start": _timestamp(data.get("current_period_start")),
        "current_period_end": _timestamp(data.get("current_period_end")),
        "last_event_at": event.created,
        "last_event_id": event.id,
        "raw": data,
    }

    plan_code = _plan_for(price_id, state, price_map)
    if plan_code is not None:
        updates["plan_code"] = plan_code

    new_state = replace(state, **updates)
    return new_state, "applied" if new_state != state else "noop"


def _payment(state: SubscriptionState, event: Event) -> tuple[SubscriptionState, Outcome]:
    """
    Payment outcomes move one field: the status.

    Deliberately not derived from the invoice amount, the period, or the plan —
    those come from the subscription snapshot, which is the authoritative source.
    An invoice that succeeds against a subscription we already know is cancelled
    changes nothing.
    """
    subscription_id = _subject_id(event)
    if subscription_id and state.external_id and subscription_id != state.external_id:
        return state, "other_object"

    if state.is_terminal:
        return state, "noop"

    succeeded = event.type in {"invoice.payment_succeeded", "invoice.paid"}
    new_status = "active" if succeeded else "past_due"

    if state.status == new_status:
        # The common case by far: every successful renewal of an active
        # subscription lands here. No write, no audit event, no email.
        return replace(state, last_event_at=event.created, last_event_id=event.id), "noop"

    return (
        replace(
            state,
            status=new_status,
            last_event_at=event.created,
            last_event_id=event.id,
        ),
        "applied",
    )


def _checkout(
    state: SubscriptionState, event: Event, price_map: dict[str, str]
) -> tuple[SubscriptionState, Outcome]:
    """
    A completed checkout, which is where a new customer comes from.

    The session does not carry the subscription object; it carries its id. The
    webhook handler hydrates it (one API call) before calling this, and the
    hydrated subscription is placed in `data["subscription_object"]`. If it
    hasn't been hydrated, this records the customer association and waits for the
    `customer.subscription.created` that Stripe always sends — which is why that
    event handler is the important one and this one is a convenience.
    """
    if event.data.get("mode") not in {None, "subscription"}:
        # A one-off payment session. Not our business in this product.
        return state, "noop"

    customer_id = event.data.get("customer")
    subscription = event.data.get("subscription_object") or {}
    if not subscription:
        if customer_id and customer_id != state.external_customer_id:
            return (
                replace(
                    state,
                    external_customer_id=str(customer_id),
                    last_event_at=event.created,
                    last_event_id=event.id,
                ),
                "applied",
            )
        return state, "noop"

    hydrated = dict(event.data)
    hydrated.update(subscription)
    return _subscription(
        state,
        replace(event, type="customer.subscription.created", data=hydrated),
        price_map,
    )


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------


def _status(data: dict[str, Any]) -> str:
    """
    The status, normalised.

    Stripe has more statuses than the product models — `incomplete_expired` is
    mapped onto `canceled`, because from the customer's point of view an
    abandoned checkout and a cancellation are the same thing: nothing is
    happening and they are not being charged.
    """
    raw = str(data.get("status") or "none")
    if raw == "incomplete_expired":
        return "canceled"
    return raw


def _price_id(data: dict[str, Any]) -> str | None:
    price = data.get("price")
    if isinstance(price, dict):
        return price.get("id")
    items = (data.get("items") or {}).get("data") or []
    if items and isinstance(items[0], dict):
        price = items[0].get("price")
        if isinstance(price, dict):
            return price.get("id")
    return None


def _plan_for(
    price_id: str | None, state: SubscriptionState, price_map: dict[str, str]
) -> str | None:
    """
    Which plan a Stripe price id corresponds to.

    An unknown price id **keeps the current plan** rather than falling back to
    free. The usual cause is a new price created in the Stripe dashboard before
    the environment variable was updated — a deploy ordering problem on our side,
    not a statement that the customer stops paying. Downgrading them for it
    would be a self-inflicted outage; keeping the plan and logging loudly gives
    whoever deploys next a chance to fix it.
    """
    if not price_id:
        return None

    mapped = price_map.get(price_id)
    if mapped and is_valid_plan(mapped):
        return mapped
    if mapped:
        log.error(
            "price map points at a plan that does not exist",
            extra={"price_id": price_id, "plan_code": mapped},
        )
        return None

    # Some plans map to a price id that wasn't configured; try the reverse of the
    # catalogue so a price id that happens to equal a plan code still works in
    # development.
    if is_valid_plan(price_id):
        return price_id

    log.warning(
        "unknown Stripe price id — keeping the current plan",
        extra={"price_id": price_id, "current_plan": state.plan_code, "known": sorted(CATALOGUE)},
    )
    return None


def _timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


def initial_state_for_new_subscription(
    price_id: str | None, price_map: dict[str, str]
) -> SubscriptionState:
    """
    What an org with no subscription row should look like when one arrives.

    A convenience for the webhook path: the org exists, Stripe says a
    subscription exists, and the two need joining without inventing a plan.
    """
    plan_code = price_map.get(price_id or "")
    return SubscriptionState(
        plan_code=plan_code if plan_code and is_valid_plan(plan_code) else "free",
        status="incomplete",
    )


def plan_name(code: str) -> str:
    return get_plan(code).name


__all__ = [
    "CHECKOUT_EVENTS",
    "HANDLED",
    "PAYMENT_EVENTS",
    "SUBSCRIPTION_EVENTS",
    "Event",
    "Outcome",
    "SubscriptionState",
    "apply_event",
    "initial_state_for_new_subscription",
    "plan_name",
]
