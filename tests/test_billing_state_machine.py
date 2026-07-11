"""
The billing state machine, without a database, a webhook or a Stripe account.

This is the most intricate pure logic in the project and it had no tests, which
is how a folder that drops its ordering clock can look healthy for a month. Every
case below is one that actually went wrong during development, or one step away
from a case that did:

  * an upgrade delivered backwards (cancel old, then create new) left the
    customer cancelled
  * a redelivered cancellation landed on an org that had been upgraded since
  * an invoice event never reached the state at all, because the code looked for
    the subscription id in a field Stripe moved
  * a price id that is not in the map yet downgraded a paying customer

`iterations` is the point of this file: folding a set of events in every possible
order and asserting on the final state is the only way to test a state machine
whose input arrives out of order.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest

from workbench.billing.state_machine import (
    Event,
    SubscriptionState,
    apply_event,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
PRICES = {"price_team": "team", "price_ent": "enterprise"}


def at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


def subscription_event(
    event_type: str,
    *,
    subscription_id: str = "sub_a",
    created: int = 0,
    status: str = "active",
    price_id: str | None = "price_team",
    quantity: int = 1,
    event_id: str | None = None,
) -> Event:
    """A payload shaped the way Stripe sends one."""
    object_: dict = {
        "id": subscription_id,
        "customer": "cus_1",
        "status": status,
        "quantity": quantity,
        "cancel_at_period_end": False,
        "current_period_start": int(at(0).timestamp()),
        "current_period_end": int(at(2_592_000).timestamp()),
    }
    if price_id is not None:
        object_["price"] = {"id": price_id}
    return Event.from_payload(
        {
            "id": event_id or f"evt_{subscription_id}_{event_type.split('.')[-1]}_{created}",
            "type": event_type,
            "created": int(at(created).timestamp()),
            "data": {"object": object_},
        }
    )


def invoice_event(
    event_type: str,
    *,
    subscription_id: str = "sub_a",
    created: int = 0,
    customer: str = "cus_1",
    nested: bool = False,
) -> Event:
    """
    An invoice event, in either of the two shapes Stripe has used.

    `nested=True` is the current API: the subscription lives under
    `parent.subscription_details`. The flat shape is what everything written
    before 2025 assumes, and the two disagree about where the id is.
    """
    object_: dict = {"customer": customer, "amount_due": 5000}
    if nested:
        object_["parent"] = {"subscription_details": {"subscription": subscription_id}}
    else:
        object_["subscription"] = subscription_id
    return Event.from_payload(
        {
            "id": f"evt_inv_{event_type.split('.')[-1]}_{created}_{nested}",
            "type": event_type,
            "created": int(at(created).timestamp()),
            "data": {"object": object_},
        }
    )


def fold(events: list[Event], state: SubscriptionState | None = None):
    """Apply events in the given order, returning the final state and outcomes."""
    current = state or SubscriptionState()
    outcomes = []
    for event in events:
        current, outcome = apply_event(current, event, price_map=PRICES)
        outcomes.append(outcome)
    return current, outcomes


# ---------------------------------------------------------------------------
# The basics
# ---------------------------------------------------------------------------


def test_a_new_subscription_sets_the_plan_from_the_price_map():
    state, outcomes = fold([subscription_event("customer.subscription.created", created=0)])

    assert outcomes == ["applied"]
    assert state.plan_code == "team"
    assert state.status == "active"
    assert state.external_id == "sub_a"


def test_statuses_the_product_does_not_model_are_mapped_not_rejected():
    """
    `incomplete_expired` is a cancellation as far as anyone outside Stripe cares.

    A billing integration that only knows the statuses it expected becomes a
    crash the first time Stripe adds one.
    """
    state, _ = fold(
        [subscription_event("customer.subscription.created", status="incomplete_expired")]
    )
    assert state.status == "canceled"


def test_an_unknown_event_type_changes_nothing():
    state, outcomes = fold(
        [Event.from_payload({"id": "evt_1", "type": "radar.early_fraud", "data": {}})]
    )
    assert outcomes == ["unhandled"]
    assert state == SubscriptionState()


def test_a_price_id_that_is_not_mapped_keeps_the_current_plan():
    """
    The realistic cause is a new price created in Stripe before the environment
    variable was updated. Downgrading a paying customer because of a deploy
    ordering mistake is a self-inflicted outage.
    """
    first, _ = fold([subscription_event("customer.subscription.created", created=0)])
    second, outcomes = fold(
        [
            subscription_event(
                "customer.subscription.updated", created=10, price_id="price_brand_new"
            )
        ],
        first,
    )

    assert outcomes == ["applied"]  # the snapshot is still applied
    assert second.plan_code == "team"  # ...but the plan is kept
    assert second.status == "active"


# ---------------------------------------------------------------------------
# Out-of-order delivery
# ---------------------------------------------------------------------------


def test_an_older_event_is_ignored_and_the_clock_does_not_move_backwards():
    created, _ = fold([subscription_event("customer.subscription.created", created=100)])
    after, outcomes = fold(
        [subscription_event("customer.subscription.updated", created=50, status="past_due")],
        created,
    )

    assert outcomes == ["stale"]
    assert after.status == "active"
    assert after.last_event_at == created.last_event_at


def test_the_clock_is_carried_on_the_state_not_recomputed():
    """`last_event_at` is Stripe's `created`, and it survives a fold."""
    state, _ = fold([subscription_event("customer.subscription.created", created=42)])
    assert state.last_event_at == at(42)
    assert state.last_event_id


@pytest.mark.parametrize(
    "events",
    [
        # An upgrade delivered backwards — this is the case that shipped broken.
        [
            subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
            subscription_event(
                "customer.subscription.deleted",
                subscription_id="sub_a",
                status="canceled",
                created=10,
            ),
            subscription_event(
                "customer.subscription.created", subscription_id="sub_b", created=20
            ),
        ],
        # The same facts in the order they "should" arrive.
        [
            subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
            subscription_event(
                "customer.subscription.created", subscription_id="sub_b", created=20
            ),
            subscription_event(
                "customer.subscription.deleted",
                subscription_id="sub_a",
                status="canceled",
                created=10,
            ),
        ],
    ],
)
def test_a_plan_change_ends_the_same_way_whatever_the_delivery_order(events):
    """
    Two interleavings of {create A, cancel A, create B}, one final state: B, active.

    This is the property the whole design rests on. Delivered in the wrong order
    — which Stripe does — the naive implementation cancels a customer who has
    just been upgraded, and the support ticket arrives within the hour.
    """
    state, _ = fold(events)

    assert state.external_id == "sub_b"
    assert state.status == "active"
    assert state.plan_code == "team"


def test_every_permutation_of_three_dependent_events_agrees():
    """
    Not just the two orders a human would write down: all six.

    Cheap to run, and it is the difference between testing the interleavings
    somebody thought of and the ones that happen.
    """
    events = [
        subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
        subscription_event(
            "customer.subscription.deleted", subscription_id="sub_a", status="canceled", created=10
        ),
        subscription_event("customer.subscription.created", subscription_id="sub_b", created=20),
    ]

    finals = set()
    for order in itertools.permutations(events):
        # Fresh ledger per order, the way a new org's row would start.
        state, _ = fold(list(order), SubscriptionState())
        finals.add((state.external_id, state.status))
        # The outcome `other_object` is allowed; `canceled` on sub_b is not.

    assert finals == {("sub_b", "active")}


def test_a_cancellation_of_a_replaced_subscription_does_not_cancel_its_successor():
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
            subscription_event(
                "customer.subscription.created", subscription_id="sub_b", created=10
            ),
        ]
    )
    after, outcomes = fold(
        [
            subscription_event(
                "customer.subscription.deleted",
                subscription_id="sub_a",
                status="canceled",
                created=20,
            )
        ],
        state,
    )

    assert outcomes == ["other_object"]
    assert after.status == "active"
    assert after.external_id == "sub_b"


def test_a_cancelled_subscription_is_not_resurrected_by_a_late_update():
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
            subscription_event(
                "customer.subscription.deleted",
                subscription_id="sub_a",
                status="canceled",
                created=10,
            ),
        ]
    )
    after, outcomes = fold(
        [subscription_event("customer.subscription.updated", subscription_id="sub_a", created=20)],
        state,
    )

    assert outcomes == ["noop"]
    assert after.status == "canceled"


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("nested", [False, True])
def test_a_failed_invoice_moves_the_org_to_past_due_in_both_payload_shapes(nested):
    """
    The subscription id moved, and looking in the old place failed silently.

    The event was folded as "no subscription id" and logged at info, so payment
    failures stopped changing anything: no error, no alert, and the first sign of
    trouble was a customer whose card had been failing for a week.
    """
    state, _ = fold([subscription_event("customer.subscription.created", created=0)])
    after, outcomes = fold(
        [invoice_event("invoice.payment_failed", created=30, nested=nested)], state
    )

    assert outcomes == ["applied"]
    assert after.status == "past_due"


@pytest.mark.parametrize("nested", [False, True])
def test_a_successful_payment_brings_the_org_back(nested):
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", created=0),
            invoice_event("invoice.payment_failed", created=10),
        ]
    )
    after, outcomes = fold(
        [invoice_event("invoice.payment_succeeded", created=20, nested=nested)], state
    )

    assert outcomes == ["applied"]
    assert after.status == "active"


def test_a_renewal_of_an_already_active_subscription_is_a_noop():
    """
    The most common event of all — every successful renewal. It must not produce
    a write, an audit event or an email.
    """
    state, _ = fold([subscription_event("customer.subscription.created", created=0)])
    after, outcomes = fold([invoice_event("invoice.paid", created=2_592_000)], state)

    assert outcomes == ["noop"]
    assert after.status == "active"


def test_a_failed_invoice_for_a_replaced_subscription_changes_nothing():
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", subscription_id="sub_a", created=0),
            subscription_event(
                "customer.subscription.created", subscription_id="sub_b", created=10
            ),
        ]
    )
    after, outcomes = fold(
        [invoice_event("invoice.payment_failed", subscription_id="sub_a", created=20)], state
    )

    assert outcomes == ["other_object"]
    assert after.status == "active"


def test_a_payment_for_a_cancelled_subscription_is_ignored():
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", created=0),
            subscription_event("customer.subscription.deleted", status="canceled", created=10),
        ]
    )
    after, outcomes = fold([invoice_event("invoice.paid", created=20)], state)

    assert outcomes == ["noop"]
    assert after.status == "canceled"


# ---------------------------------------------------------------------------
# The end of a trial, and checkouts
# ---------------------------------------------------------------------------


def test_trial_will_end_is_a_courtesy_not_a_state_change():
    """
    It arrives three days *before* the trial ends. Acting on it would be a write
    whose only effect is to make the row agree with itself.
    """
    state, _ = fold(
        [
            subscription_event("customer.subscription.created", created=0),
            subscription_event("customer.subscription.trial_will_end", created=10),
        ]
    )

    assert state.status == "active"
    assert state.last_event_at == at(0)


def test_a_checkout_without_the_hydrated_subscription_records_the_customer():
    """
    One API call at the time of the event is not always possible, and the design
    does not depend on it: `customer.subscription.created` always follows.
    """
    event = Event.from_payload(
        {
            "id": "evt_checkout",
            "type": "checkout.session.completed",
            "created": int(at(5).timestamp()),
            "data": {"object": {"id": "cs_1", "mode": "subscription", "customer": "cus_9"}},
        }
    )
    state, outcomes = fold([event])

    assert outcomes == ["applied"]
    assert state.external_customer_id == "cus_9"
    assert state.external_id is None  # nothing invented


def test_a_one_off_payment_session_is_not_a_subscription():
    event = Event.from_payload(
        {
            "id": "evt_checkout2",
            "type": "checkout.session.completed",
            "created": int(at(5).timestamp()),
            "data": {"object": {"id": "cs_2", "mode": "payment", "customer": "cus_9"}},
        }
    )
    state, outcomes = fold([event])

    assert outcomes == ["noop"]
    assert state == SubscriptionState()


def test_a_hydrated_checkout_becomes_the_subscription_immediately():
    """The webhook handler hydrates the session; the fold is then a plain create."""
    event = Event.from_payload(
        {
            "id": "evt_checkout3",
            "type": "checkout.session.completed",
            "created": int(at(5).timestamp()),
            "data": {
                "object": {
                    "id": "cs_3",
                    "mode": "subscription",
                    "customer": "cus_9",
                    "subscription_object": {
                        "id": "sub_hydrated",
                        "customer": "cus_9",
                        "status": "active",
                        "price": {"id": "price_team"},
                    },
                }
            },
        }
    )
    state, outcomes = fold([event])

    assert outcomes == ["applied"]
    assert state.external_id == "sub_hydrated"
    assert state.plan_code == "team"


def test_events_without_an_id_are_dropped_rather_than_guessed_at():
    """A malformed event is logged and folded away; it never moves the row."""
    event = Event.from_payload(
        {
            "id": "evt_noid",
            "type": "customer.subscription.updated",
            "created": int(at(5).timestamp()),
            "data": {"object": {"customer": "cus_1", "status": "active"}},
        }
    )
    state, outcomes = fold([event])

    assert outcomes == ["noop"]
    assert state == SubscriptionState()
