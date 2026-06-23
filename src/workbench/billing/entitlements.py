"""
Entitlement resolution.

One pure function answers "what may this org do right now", from three inputs:

    plan  ← the active subscription, or free
    overrides ← per-org values written by staff, always audited
    usage ← what's been consumed this period

Entitlements are *resolved*, never inferred. Code that reads `org.plan == "team"`
to decide whether to enable SSO is code that will be wrong the first time a deal
gets a custom override — and the bug will be a customer getting a feature they
didn't pay for, which nobody reports.

The resolution order, and why:

    1. Staff override      — an explicit commercial decision beats everything
    2. Active subscription — what they're paying for
    3. Catalogue default   — the free tier

Every step is a pure dict merge, so the whole module is testable without a
database, a Stripe account, or a clock.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal

from workbench.billing.plans import CATALOGUE, DEFAULT_PLAN, Plan, get_plan

# Overrides are deliberately a small, closed set. A free-form JSON blob that any
# key can land in is an entitlement system nobody can reason about.
OVERRIDABLE: frozenset[str] = frozenset(
    {
        "seats",
        "monthly_requests",
        "retention_days",
        "max_projects",
        "max_api_keys",
        "max_webhooks",
        "api_rate_limit_per_minute",
        "sso",
        "audit_log",
        "priority_support",
        "custom_domain",
        "overage",
    }
)

SubscriptionStatus = Literal[
    "active", "trialing", "past_due", "unpaid", "canceled", "incomplete", "none"
]

# Which statuses grant access. This set is the answer to "the payment failed,
# do we turn off the product". `past_due` is included on purpose: a card that
# expired this morning should not take a customer's integration down, and
# dunning exists precisely to resolve it. `unpaid` and `canceled` do not.
GRANTING_STATUSES: frozenset[str] = frozenset({"active", "trialing", "past_due"})

# Losing access isn't all-or-nothing. Reads keep working for a grace period so
# a customer can export before they go; writes stop immediately.
READ_GRACE_DAYS: dict[str, int] = {
    "unpaid": 14,
    "canceled": 30,
    "incomplete": 3,
    "past_due": 7,
    "none": 0,
}


class QuotaExceeded(PermissionError):
    """Raised by `Entitlements.require()`. Routers translate to 402 or 429."""

    def __init__(self, entitlement: str, limit: Any, used: Any, plan: str) -> None:
        super().__init__(f"{entitlement} limit reached on the {plan} plan ({used}/{limit})")
        self.entitlement = entitlement
        self.limit = limit
        self.used = used
        self.plan = plan


class FeatureNotIncluded(PermissionError):
    def __init__(self, feature: str, plan: str) -> None:
        super().__init__(f"{feature} is not included in the {plan} plan")
        self.feature = feature
        self.plan = plan


@dataclass(frozen=True, slots=True)
class Subscription:
    """The subset of a subscription that entitlement resolution needs."""

    plan_code: str
    status: SubscriptionStatus
    current_period_end: Any = None
    cancel_at_period_end: bool = False
    quantity: int = 1
    provider: str = "stripe"

    @property
    def grants_access(self) -> bool:
        return self.status in GRANTING_STATUSES

    @property
    def is_paid(self) -> bool:
        return self.plan_code != DEFAULT_PLAN

    def __repr__(self) -> str:
        return f"<Subscription {self.plan_code}/{self.status}>"


@dataclass(frozen=True, slots=True)
class Usage:
    """Consumption for the current period."""

    seats: int = 0
    requests_this_month: int = 0
    projects: int = 0
    api_keys: int = 0
    webhooks: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "seats": self.seats,
            "requests_this_month": self.requests_this_month,
            "projects": self.projects,
            "api_keys": self.api_keys,
            "webhooks": self.webhooks,
        }


@dataclass(frozen=True, slots=True)
class Entitlements:
    """What an org may do right now. Every field is resolved; none are inferred."""

    plan: Plan
    subscription: Subscription | None
    usage: Usage
    overrides: dict[str, Any] = field(default_factory=dict)

    # -- resolution ---------------------------------------------------------

    @classmethod
    def resolve(
        cls,
        *,
        subscription: Subscription | None = None,
        overrides: dict[str, Any] | None = None,
        usage: Usage | None = None,
    ) -> Entitlements:
        overrides = _sanitise_overrides(overrides or {})

        if subscription is None or not subscription.grants_access:
            # A lapsed subscription drops to free *plus* whatever was negotiated
            # by hand — a customer in a signed contract that's mid-migration
            # shouldn't lose Enterprise limits because a webhook was missed.
            base = get_plan(DEFAULT_PLAN)
            if subscription is not None and subscription.is_paid:
                base = get_plan(subscription.plan_code)
        else:
            base = get_plan(subscription.plan_code)

        plan = replace(base, **overrides) if overrides else base
        return cls(
            plan=plan, subscription=subscription, usage=usage or Usage(), overrides=overrides
        )

    # -- feature gates ------------------------------------------------------

    def allows(self, feature: str) -> bool:
        """Check a boolean feature. Unknown features are denied, not allowed."""
        attribute = FEATURE_ATTRIBUTES.get(feature)
        if attribute is None:
            return False
        return bool(getattr(self.plan, attribute, False))

    def require_feature(self, feature: str) -> None:
        if not self.allows(feature):
            raise FeatureNotIncluded(feature, self.plan.code)

    # -- quota gates --------------------------------------------------------

    def remaining(self, entitlement: str) -> int | None:
        """None means unlimited. Never returns a negative number."""
        limit = self.limit_for(entitlement)
        if limit is None:
            return None
        return max(0, limit - self.used_for(entitlement))

    def limit_for(self, entitlement: str) -> int | None:
        attribute = QUOTA_ATTRIBUTES.get(entitlement)
        if attribute is None:
            raise KeyError(f"unknown entitlement '{entitlement}'")
        return getattr(self.plan, attribute, None)

    def used_for(self, entitlement: str) -> int:
        return self.usage.as_dict().get(entitlement, 0)

    def is_exhausted(self, entitlement: str) -> bool:
        remaining = self.remaining(entitlement)
        return remaining == 0

    def would_exceed(self, entitlement: str, adding: int = 1) -> bool:
        limit = self.limit_for(entitlement)
        if limit is None:
            return False
        return self.used_for(entitlement) + adding > limit

    def require(self, entitlement: str, adding: int = 1) -> None:
        """
        Raise if this action would exceed the limit.

        Free plans hard-stop. Paid plans with `soft` overage are allowed through
        and expected to call `overage_units()` afterwards to record the excess —
        the caller decides because only the caller knows whether the work already
        happened.
        """
        limit = self.limit_for(entitlement)
        if limit is None:
            return
        used = self.used_for(entitlement)
        if used + adding <= limit:
            return
        if self.plan.overage in {"soft", "metered"} and not self.plan.is_free:
            return
        raise QuotaExceeded(entitlement, limit, used, self.plan.code)

    def require_with_reserved(self, entitlement: str, reserved: int, *, adding: int = 1) -> None:
        """
        Raise unless there is room for `adding` more, counting `reserved` as spent.

        Seats are the only entitlement that needs this. An invitation is a promise
        — once it is sent, somebody will click it — so an org on a three-seat plan
        should hear "no" when it sends the third invitation, not when the third
        colleague accepts it. Yet the seat count that matters at *acceptance* time
        has to stay the count of real members, or the invitation being accepted
        would be counted twice: once as a pending reservation and once as the
        membership it becomes.

        So the number lives at the call site where the promise is made. The 402
        that comes out of here reports seats plus reservations as "used", which
        is the number the customer can actually see in their member list.
        """
        limit = self.limit_for(entitlement)
        if limit is None:
            return
        used = self.used_for(entitlement)
        if used + reserved + adding <= limit:
            return
        if self.plan.overage in {"soft", "metered"} and not self.plan.is_free:
            return
        raise QuotaExceeded(entitlement, limit, used + reserved, self.plan.code)

    def overage_units(self, entitlement: str) -> int:
        limit = self.limit_for(entitlement)
        if limit is None:
            return 0
        return max(0, self.used_for(entitlement) - limit)

    # -- lifecycle ----------------------------------------------------------

    @property
    def is_over_quota(self) -> bool:
        return bool(
            self.plan.monthly_requests is not None
            and self.usage.requests_this_month > self.plan.monthly_requests
        )

    @property
    def usage_ratio(self) -> float:
        return self.plan.usage_ratio(self.usage.requests_this_month)

    @property
    def is_near_quota(self) -> bool:
        from workbench.core.settings import get_settings

        ratio = self.usage_ratio
        return 0.0 < ratio < 1.0 and ratio >= get_settings().usage_soft_warn_ratio

    @property
    def is_read_only(self) -> bool:
        """
        True when writes are refused but reads still work.

        This is the state a customer is in after a failed payment. It's a real
        state, not a bug, and the product should say so in the UI rather than
        returning a generic 403 on save.
        """
        if self.subscription is None:
            return False
        return not self.subscription.grants_access

    def read_grace_days(self) -> int:
        if self.subscription is None:
            return 0
        return READ_GRACE_DAYS.get(self.subscription.status, 0)

    def to_dict(self) -> dict[str, Any]:
        """Everything the frontend needs to render the billing screen in one call."""
        return {
            "plan": {
                "code": self.plan.code,
                "name": self.plan.name,
                "description": self.plan.description,
            },
            "limits": {
                "seats": self.plan.seats,
                "monthly_requests": self.plan.monthly_requests,
                "retention_days": self.plan.retention_days,
                "max_projects": self.plan.max_projects,
                "max_api_keys": self.plan.max_api_keys,
                "max_webhooks": self.plan.max_webhooks,
                "api_rate_limit_per_minute": self.plan.api_rate_limit_per_minute,
            },
            "features": sorted(f for f in FEATURE_ATTRIBUTES if self.allows(f)),
            "usage": {
                **self.usage.as_dict(),
                "ratio": round(self.usage_ratio, 4),
                "over_quota": self.is_over_quota,
            },
            "remaining": {
                key: self.remaining(key)
                for key in ("seats", "requests_this_month", "projects", "api_keys", "webhooks")
            },
            "overage": self.plan.overage,
            "is_read_only": self.is_read_only,
            "read_grace_days": self.read_grace_days(),
            "overrides": sorted(self.overrides),
            "subscription": (
                {
                    "status": self.subscription.status,
                    "plan_code": self.subscription.plan_code,
                    "cancel_at_period_end": self.subscription.cancel_at_period_end,
                    "current_period_end": (
                        self.subscription.current_period_end.isoformat()
                        if self.subscription.current_period_end
                        else None
                    ),
                }
                if self.subscription
                else None
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<Entitlements plan={self.plan.code} "
            f"requests={self.usage.requests_this_month}/{self.plan.monthly_requests}>"
        )


# Entitlement name → Plan attribute. Kept as dicts so the names the API exposes
# and the names the dataclass uses can differ without either becoming a lie.
QUOTA_ATTRIBUTES: dict[str, str] = {
    "seats": "seats",
    "requests_this_month": "monthly_requests",
    "projects": "max_projects",
    "api_keys": "max_api_keys",
    "webhooks": "max_webhooks",
}

FEATURE_ATTRIBUTES: dict[str, str] = {
    "sso": "sso",
    "audit_log": "audit_log",
    "audit_export": "audit_log",
    "priority_support": "priority_support",
    "custom_domain": "custom_domain",
    "data_residency": "data_residency",
}


def _sanitise_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Drop anything not in OVERRIDABLE, and validate what's left.

    An unrecognised key in an override blob is either a typo or an attempt to
    grant something the system doesn't model. Neither should be silently
    accepted — a typo'd override that does nothing is worse than a rejection,
    because the deal's terms are then not what anyone thinks they are.
    """
    clean: dict[str, Any] = {}

    for key, value in raw.items():
        if key not in OVERRIDABLE:
            continue
        if key == "overage":
            if value in {"hard", "soft", "metered"}:
                clean[key] = value
            continue
        if key in {"sso", "audit_log", "priority_support", "custom_domain"}:
            clean[key] = bool(value)
            continue
        # Numeric limits: None means unlimited, which is a real commercial term.
        if value is None:
            clean[key] = None
        elif isinstance(value, int) and value >= 0:
            clean[key] = value

    return clean


def resolve_from_orm(org: Any, subscription_row: Any | None = None, **usage: int) -> Entitlements:
    """
    Adapter for the router layer: turn ORM rows into an Entitlements value.

    Kept here rather than in the router so that the mapping from storage to
    entitlements is testable without a database.
    """
    subscription = None
    if subscription_row is not None:
        subscription = Subscription(
            plan_code=subscription_row.plan_code,
            status=subscription_row.status,
            current_period_end=getattr(subscription_row, "current_period_end", None),
            cancel_at_period_end=getattr(subscription_row, "cancel_at_period_end", False),
            quantity=getattr(subscription_row, "quantity", 1),
            provider=getattr(subscription_row, "provider", "stripe"),
        )

    return Entitlements.resolve(
        subscription=subscription,
        overrides=getattr(org, "overrides", None) or {},
        usage=Usage(**usage),
    )


def all_plans() -> list[dict[str, Any]]:
    """The public plan list, for the pricing page and the admin console."""
    return [
        {
            "code": plan.code,
            "name": plan.name,
            "description": plan.description,
            "limits": {
                "seats": plan.seats,
                "monthly_requests": plan.monthly_requests,
                "retention_days": plan.retention_days,
                "max_projects": plan.max_projects,
            },
            "features": sorted(
                f for f in FEATURE_ATTRIBUTES if getattr(plan, FEATURE_ATTRIBUTES[f], False)
            ),
            "overage": plan.overage,
        }
        for plan in CATALOGUE.values()
    ]
