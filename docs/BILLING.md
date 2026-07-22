# Billing and entitlements

How money gets in, and how the product decides what a customer may do.

---

## The split that keeps this maintainable

| Concern | Lives in | Changes when |
|---|---|---|
| What a plan costs | Stripe | Pricing changes |
| What a plan *allows* | `billing/plans.py` | Product changes |
| What this org is entitled to | `billing/entitlements.py` | Every request |
| What this org has consumed | `usage_records` | Every request |
| What a customer negotiated | `plan_overrides` | A deal closes |

Plans are code. Stripe owns the amount and the currency; the application owns the
limits. A plan row in a database drifts — someone edits production to close a
deal, the edit never reaches staging, and now the two environments disagree about
what "Enterprise" means. A plan in git is reviewed in a pull request and lands
everywhere at once.

---

## Entitlement resolution

One pure function:

```python
ent = Entitlements.resolve(subscription=sub, overrides=org.overrides, usage=usage)
```

Order, and why:

```
1. Staff override        an explicit commercial decision beats everything
2. Active subscription   what they're paying for
3. Catalogue default     the free tier
```

Every step is a dict merge. No database, no Stripe call, no clock. That's the
point: the code that decides whether a customer gets a feature should be the
easiest code in the system to test, because its bugs turn into refunds.

### Subscription statuses

| Status | Access | Limits | Notes |
|---|---|---|---|
| `active` | full | plan | |
| `trialing` | full | plan | |
| `past_due` | full | plan | A card that expired this morning must not take down a customer's integration |
| `unpaid` | read-only | plan | 14 days of read grace |
| `canceled` | read-only | plan | 30 days of read grace |
| `incomplete` | read-only | plan | 3 days — the checkout was never finished |
| `incomplete_expired` | none | free | |

The important row is `past_due`. It's tempting to cut access immediately; don't.
Dunning exists precisely to resolve it, and the customer's team is mid-sprint.

Losing access is also not all-or-nothing. Reads keep working through a grace
period so a customer can export before they go. Writes stop immediately. That's
`Entitlements.is_read_only`, and the frontend is expected to show a banner
rather than letting saves fail with a generic 403.

### Overrides

Written by staff, always with a reason, always audited, optionally expiring:

```python
{"seats": 50, "sso": True}                 # a deal
{"monthly_requests": None}                 # unlimited, for a migration
{"monthly_requests": 5_000_000}            # a temporary bump
```

`OVERRIDABLE` is a closed set. A free-form JSON blob that any key can land in is
an entitlement system nobody can reason about, and a typo'd key that silently
does nothing is worse than a rejection — the deal's terms are then not what
anyone thinks they are.

Unknown keys are dropped rather than stored. `test_override_keeps_only_valid_keys`
covers it.

---

## Over-quota behaviour

Per plan, not global:

| Plan | Policy | Why |
|---|---|---|
| free | `hard` | Refuse. The alternative is silently accruing a bill nobody agreed to |
| team | `soft` | Allow, warn, record overage. Cutting off a paying customer mid-month is a refund conversation, not an upsell |
| enterprise | `metered` | Allow, bill, and don't pretend there's a ceiling |

```python
ent.require("requests_this_month")   # raises QuotaExceeded on free, passes on team
ent.overage_units("requests_this_month")  # what to bill
```

The asymmetry is deliberate. A free user hitting the limit should be told to
upgrade. A paying user hitting the limit should keep working and see it on the
invoice.

---

## Webhooks

The part that goes wrong in every billing integration.

### The order is not optional

```
1. BEGIN
2. INSERT INTO stripe_events (event_id, ...)     ← unique constraint
3. ... do the work ...
4. record processed_at
5. COMMIT
```

A unique violation at step 2 means Stripe has delivered this event before.
Roll back, return 200, move on.

Doing the work first and recording it afterwards is the version that sends the
upgrade email twice, because a crash between those two steps means Stripe retries
and you run it again. The constraint is the idempotency; the code around it is
just bookkeeping.

### Delivery order is not guaranteed either

Stripe will happily deliver `customer.subscription.updated` before
`checkout.session.completed`. Code that assumes otherwise creates a subscription
in a state that never existed.

The rule here: **every webhook handler is written to be order-independent.** Each
one fetches the current object from the Stripe API and stores what it finds,
rather than applying a delta to what it believes. That costs one API call per
event and removes an entire class of bug.

### What each event does

| Event | Effect |
|---|---|
| `checkout.session.completed` | Link the Stripe customer to the org, create/update the subscription |
| `customer.subscription.created/updated` | Set plan, status, period, `cancel_at_period_end` |
| `customer.subscription.deleted` | Status `canceled`, keep the plan for the read grace |
| `invoice.paid` | Clear dunning, record the success in the audit log |
| `invoice.payment_failed` | Start or advance dunning, audit it |
| `customer.updated` | Refresh the cached email and tax ids |

Anything unrecognised is stored and ignored. An unknown event type is not an
error; treating it as one means a Stripe addition becomes your outage.

---

## Usage metering

```sql
UPDATE usage_records
   SET quantity = quantity + :n
 WHERE org_id = :org AND meter = 'requests' AND period_start = :period;
```

Atomic, inside the transaction that did the work. A rollback un-counts it.

The tempting alternative is a Redis counter flushed to Postgres every minute.
It's faster and it produces a month where the numbers don't match — which is the
month a customer disputes an invoice and you have no answer. Use Redis as a
*read cache* in front of this table, never as the source of truth.

`included` is snapshotted at the start of the period, so a mid-month upgrade
doesn't retroactively change what the first half of the month cost.

---

## Dunning

Three emails, then escalation:

| Step | When | What it says |
|---|---|---|
| 1 | day 0 | "Your payment didn't go through." Link to update the card. |
| 2 | day 3 | "Still failing — here's the exact error from your bank." |
| 3 | day 7 | "Your account becomes read-only on day 14." Names the date. |

Every attempt is a `dunning_attempts` row, so support can see exactly which
messages a customer has already received before they call in. The step counter
has an upper bound; a sequence that can loop forever will.

---

## Testing this without Stripe

Three layers, each catching different things:

1. **Pure resolution** — `test_entitlements.py`. Plan maths, overrides, statuses,
   quota behaviour. No database, no network, 60 assertions.
2. **Idempotency** — insert the same `stripe_events.event_id` twice and assert the
   second attempt is refused and no work happens.
3. **Ordering** — deliver a subset of events out of order and assert the final
   state matches what Stripe would say, which is checked by fetching the object.

`make stripe-listen` forwards real test-mode events to the local API. Useful once,
for confidence; not a substitute for the three layers above, because you cannot
make Stripe deliver an event twice on demand.

---

## Things that will bite you

- **Timezone drift on period boundaries.** `current_period_end` is a UTC instant.
  Comparing it against a local `datetime.now()` is how you get an entitlement
  that expires an hour early or late. Everything here is timezone-aware.
- **A plan change mid-period and proration.** Stripe handles the money; the only
  thing to get right on your side is that `included` doesn't change retroactively.
- **Quantity-based seats.** Seat counts change on invite and on removal, and the
  Stripe subscription quantity must follow. Reconcile on a schedule rather than
  trusting the webhooks alone — one missed delivery is a permanently wrong
  invoice.
- **Overrides with no expiry.** A trial extension that nobody remembers setting
  is a permanent discount. Set `expires_at`.
