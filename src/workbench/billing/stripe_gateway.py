"""
Talking to Stripe.

Two things here are worth more than the API calls around them:

**Signature verification is written by hand.** Eight lines of HMAC, and the SDK
has `construct_event` which does the same thing. The reason not to use it is that
the SDK's version raises `SignatureVerificationError` for a bad signature *and*
for a missing one, so a misconfigured `STRIPE_WEBHOOK_SECRET` and a forged
request look identical in the logs — and one of them is an incident. Doing it here
means the failure says which. It is also the piece that has to be right when the
SDK is 40 MB of code you don't audit, and `hmac.compare_digest` is not optional.

The tolerance window is 300 seconds, and it is not paranoia: without it, anybody
who captures one webhook body can replay it forever. With it, they have five
minutes, and the idempotency ledger in `stripe_events` covers those five minutes.

**The API calls are lazy.** `import stripe` happens inside the methods, not at
module import. The API process starts in half the time, a deployment without
billing configured never loads it, and the test suite doesn't need the package
installed to import this module and test the signature code.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from typing import Any

from workbench.core.settings import Settings, get_settings

log = logging.getLogger(__name__)

SIGNATURE_TOLERANCE_SECONDS = 300


class StripeError(Exception):
    """Any refusal from this module. Mapped to a 400 or a 503 by the caller."""


class SignatureError(StripeError):
    """The request did not come from Stripe, or did not come from Stripe recently."""


class BillingNotConfigured(StripeError):
    """Stripe keys are absent. Routes that need them return 503, not 500."""


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


def verify_signature(
    payload: bytes,
    header: str | None,
    secret: str | None,
    *,
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
    now: float | None = None,
) -> None:
    """
    Verify a `Stripe-Signature` header. Raises `SignatureError` or returns None.

    The header looks like `t=1727000000,v1=hex,v1=hex`. Several `v1` values appear
    during a signing-secret rotation, and any of them matching is success — the
    alternative is a window where every webhook fails while the old secret is
    still live in Stripe's dashboard.
    """
    if not secret:
        raise BillingNotConfigured("STRIPE_WEBHOOK_SECRET is not set")
    if not header:
        raise SignatureError("missing Stripe-Signature header")

    timestamp: str | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)

    if not timestamp or not signatures:
        raise SignatureError("malformed Stripe-Signature header")

    try:
        signed_at = int(timestamp)
    except ValueError as exc:
        raise SignatureError("malformed timestamp in Stripe-Signature") from exc

    current = time.time() if now is None else now
    age = abs(current - signed_at)
    if age > tolerance:
        # Replay protection. The message names the actual problem: an age of
        # 86400 is a clock problem or a replay, and neither is a forged
        # signature — saying "invalid signature" sends someone down the wrong
        # path for an hour.
        raise SignatureError(f"webhook timestamp is {int(age)}s outside the {tolerance}s tolerance")

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode() + payload,
        hashlib.sha256,
    ).hexdigest()

    # compare_digest over every candidate, without short-circuiting on the first
    # match: `in` on a list of strings is a timing signal, and this is the one
    # comparison in the codebase where that matters most.
    matched = False
    for candidate in signatures:
        if hmac.compare_digest(expected, candidate):
            matched = True
    if not matched:
        raise SignatureError("signature does not match — check STRIPE_WEBHOOK_SECRET")


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CheckoutSession:
    id: str
    url: str


@dataclass(slots=True)
class PortalSession:
    url: str


class StripeGateway:
    """
    A thin wrapper, with three opinions:

      * an org's Stripe customer is created once and reused, because two customer
        objects for one org means a customer whose invoices are split in half
      * every object carries `metadata.org_id`, which is how a webhook that
        arrives for an unknown customer still finds its org
      * `idempotency_key` is passed on writes, so a retried request after a
        timeout does not create a second subscription
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @property
    def is_configured(self) -> bool:
        return bool(self.settings.stripe_secret_key)

    def _client(self) -> Any:
        if not self.is_configured:
            raise BillingNotConfigured("STRIPE_SECRET_KEY is not set")
        import stripe  # imported here, see the module docstring

        return stripe

    def price_for(self, plan_code: str) -> str:
        price_id = self.settings.stripe_price_for(plan_code)
        if not price_id:
            raise BillingNotConfigured(
                f"no Stripe price configured for the '{plan_code}' plan — set "
                f"STRIPE_PRICE_IDS to a JSON map of plan code to price id"
            )
        return price_id

    def plan_for_price(self, price_id: str) -> str | None:
        for code, candidate in self.settings.stripe_price_ids.items():
            if candidate == price_id:
                return code
        return None

    async def create_checkout_session(
        self,
        *,
        org_id: str,
        plan_code: str,
        customer_id: str | None,
        customer_email: str | None,
        success_url: str,
        cancel_url: str,
        quantity: int = 1,
    ) -> CheckoutSession:
        """
        A Checkout session for a subscription.

        `client_reference_id` is set to the org id. It survives the round trip
        through Stripe's hosted page and comes back on the webhook, which is what
        lets `checkout.session.completed` attach a subscription to an org without
        a lookup that might fail.
        """
        stripe = self._client()
        params: dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": self.price_for(plan_code), "quantity": quantity}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "client_reference_id": org_id,
            "metadata": {"org_id": org_id, "plan_code": plan_code},
            "subscription_data": {"metadata": {"org_id": org_id}},
            # Tax is the customer's jurisdiction, not ours to guess. Leaving this
            # off means an EU customer gets an invoice without VAT on it.
            "automatic_tax": {"enabled": True},
            "allow_promotion_codes": True,
        }
        if customer_id:
            params["customer"] = customer_id
        elif customer_email:
            params["customer_email"] = customer_email

        try:
            session = await stripe.checkout.Session.create_async(**params)
        except Exception as exc:  # noqa: BLE001 — the SDK raises its own hierarchy
            log.exception("stripe checkout session failed", extra={"org_id": org_id})
            raise StripeError(f"could not start checkout: {type(exc).__name__}") from exc

        return CheckoutSession(id=session["id"], url=session["url"])

    async def create_portal_session(self, *, customer_id: str, return_url: str) -> PortalSession:
        """
        The Billing Portal, so we don't build a card form.

        Payment details, invoices, cancellation and plan changes all live behind
        this one call. Building any of them is PCI scope for a card form, and a
        support burden for the rest.
        """
        stripe = self._client()
        try:
            session = await stripe.billing_portal.Session.create_async(
                customer=customer_id, return_url=return_url
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("stripe portal session failed", extra={"customer": customer_id})
            raise StripeError(f"could not open the billing portal: {type(exc).__name__}") from exc

        return PortalSession(url=session["url"])

    async def fetch_subscription(self, subscription_id: str) -> dict[str, Any]:
        """
        Hydrate a subscription from Stripe.

        Called from the webhook handler for `checkout.session.completed`, which
        carries an id and not much else. This is the one synchronous API call in
        the webhook path, and it is why the handler has a retry budget: Stripe
        gives an endpoint a few seconds and then retries with backoff, and a
        retried event is exactly what the idempotency ledger exists for.
        """
        stripe = self._client()
        try:
            return await stripe.Subscription.retrieve_async(subscription_id)
        except Exception as exc:  # noqa: BLE001
            raise StripeError(f"could not fetch subscription: {type(exc).__name__}") from exc

    async def cancel_subscription(
        self, subscription_id: str, *, at_period_end: bool = True
    ) -> dict[str, Any]:
        """
        Cancel, immediately or at the end of the period.

        At period end by default: the customer paid for this month and taking it
        away on the day they click cancel is how a cancellation becomes a refund.
        """
        stripe = self._client()
        try:
            if at_period_end:
                return await stripe.Subscription.modify_async(
                    subscription_id, cancel_at_period_end=True
                )
            return await stripe.Subscription.cancel_async(subscription_id)
        except Exception as exc:  # noqa: BLE001
            raise StripeError(f"could not cancel the subscription: {type(exc).__name__}") from exc


_gateway: StripeGateway | None = None


def get_gateway() -> StripeGateway:
    """Process-wide gateway. Constructing one per request would re-import the SDK."""
    global _gateway
    if _gateway is None:
        _gateway = StripeGateway()
    return _gateway


__all__ = [
    "BillingNotConfigured",
    "CheckoutSession",
    "PortalSession",
    "SignatureError",
    "StripeError",
    "StripeGateway",
    "get_gateway",
    "verify_signature",
]
