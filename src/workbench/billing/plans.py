"""
The plan catalogue.

Plans are code, not rows. Three reasons:

1. A pricing change is a pull request. It gets reviewed, it's in the git history,
   and it lands identically in every environment at deploy time.
2. Plan rows in a table drift. Somebody edits production to close a deal, the
   edit is never backported, and now staging and prod disagree about what
   "Enterprise" means.
3. Tests can assert on the catalogue directly, including properties like
   "every paid plan has a Stripe price id" and "no plan is cheaper than the tier
   below it".

Stripe owns the *price* (the amount, the currency, the billing interval) because
that's where money actually moves. This module owns the *limits*, because that's
what the application enforces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal, cast

PlanCode = Literal["free", "team", "enterprise"]

# How over-quota behaviour differs, and why it's per plan rather than global:
#
#   hard    — refuse the request. Right for free, where the alternative is
#             silently accruing a bill nobody agreed to.
#   soft    — allow it, warn the org, record overage. Right for paid tiers,
#             because cutting off a paying customer mid-month is a refund
#             conversation, not an upsell.
#   metered — allow it, bill it. Right for deliberately usage-priced work.
OveragePolicy = Literal["hard", "soft", "metered"]


@dataclass(frozen=True, slots=True)
class Plan:
    code: PlanCode
    name: str
    description: str

    seats: int | None  # None means unlimited
    monthly_requests: int | None
    retention_days: int
    overage: OveragePolicy

    max_projects: int | None = None
    max_api_keys: int = 5
    max_webhooks: int = 3
    api_rate_limit_per_minute: int = 60

    sso: bool = False
    audit_log: bool = True
    priority_support: bool = False
    custom_domain: bool = False
    data_residency: tuple[str, ...] = ("eu",)

    features: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.seats is not None and self.seats < 1:
            raise ValueError(f"plan {self.code}: seats must be positive or None")
        if self.monthly_requests is not None and self.monthly_requests < 1:
            raise ValueError(f"plan {self.code}: monthly_requests must be positive or None")
        if self.retention_days < 1:
            raise ValueError(
                f"plan {self.code}: retention must be at least a day, "
                "otherwise the product can't show a customer yesterday"
            )

    @property
    def is_free(self) -> bool:
        return self.code == "free"

    @property
    def is_unlimited(self) -> bool:
        return self.seats is None and self.monthly_requests is None

    def seat_limit_reached(self, current: int) -> bool:
        return self.seats is not None and current >= self.seats

    def requests_exhausted(self, used: int) -> bool:
        return self.monthly_requests is not None and used >= self.monthly_requests

    def usage_ratio(self, used: int) -> float:
        """0.0–1.0+ against the monthly quota. Unlimited plans report 0.0."""
        if self.monthly_requests is None:
            return 0.0
        return used / self.monthly_requests


CATALOGUE: Final[dict[PlanCode, Plan]] = {
    "free": Plan(
        code="free",
        name="Free",
        description="For trying it out. Three seats, a thousand requests, a week of history.",
        seats=3,
        monthly_requests=1_000,
        retention_days=7,
        overage="hard",
        max_projects=1,
        max_api_keys=2,
        max_webhooks=1,
        api_rate_limit_per_minute=30,
        sso=False,
        priority_support=False,
        custom_domain=False,
        features=("community_support",),
    ),
    "team": Plan(
        code="team",
        name="Team",
        description="For a working team. 25 seats, 100k requests, 90 days of history.",
        seats=25,
        monthly_requests=100_000,
        retention_days=90,
        overage="soft",
        max_projects=25,
        max_api_keys=20,
        max_webhooks=10,
        api_rate_limit_per_minute=300,
        sso=False,
        priority_support=False,
        custom_domain=True,
        features=("email_support", "custom_domain"),
    ),
    "enterprise": Plan(
        code="enterprise",
        name="Enterprise",
        description="Unlimited seats and requests. SSO, audit export, named support.",
        seats=None,
        monthly_requests=None,
        retention_days=730,
        overage="metered",
        max_projects=None,
        max_api_keys=100,
        max_webhooks=50,
        api_rate_limit_per_minute=2_000,
        sso=True,
        priority_support=True,
        custom_domain=True,
        data_residency=("eu", "us"),
        features=("sso", "audit_export", "named_support", "custom_domain", "data_residency"),
    ),
}

DEFAULT_PLAN: Final[PlanCode] = "free"


def get_plan(code: str) -> Plan:
    """
    Look up a plan. Unknown codes fall back to free rather than raising.

    Rationale: a plan code can arrive from a Stripe webhook, an old subscription
    row, or a database someone edited by hand. Falling back to the most
    restrictive plan means the failure mode is "customer temporarily downgraded"
    rather than "customer has unlimited access because of a typo".
    """
    # Same bridge as `permissions_for`: the catalogue is keyed by the literal so a
    # typo in the table is a type error, and `code` arrives as a plain string from
    # the database. Unknown codes are a supported input with a defined behaviour,
    # not a crash.
    return CATALOGUE.get(cast(PlanCode, code), CATALOGUE[DEFAULT_PLAN])


def is_valid_plan(code: str) -> bool:
    return code in CATALOGUE


def upgrade_path(code: str) -> tuple[Plan, ...]:
    """Plans a customer on `code` can move up to, cheapest first."""
    order: tuple[PlanCode, ...] = ("free", "team", "enterprise")
    try:
        index = order.index(code)  # type: ignore[arg-type]
    except ValueError:
        index = 0
    return tuple(CATALOGUE[c] for c in order[index + 1 :])


def downgrade_path(code: str) -> tuple[Plan, ...]:
    order: tuple[PlanCode, ...] = ("free", "team", "enterprise")
    try:
        index = order.index(code)  # type: ignore[arg-type]
    except ValueError:
        return ()
    return tuple(reversed([CATALOGUE[c] for c in order[:index]]))


def seat_downgrade_blockers(plan: Plan, current_seats_used: int) -> int:
    """
    How many members must be removed before this plan can be applied.

    Called before a downgrade is allowed. A plan change that silently leaves an
    org over its seat limit is worse than refusing the change — the org keeps
    working until someone tries to invite, and then the error message makes no
    sense to them.
    """
    if plan.seats is None:
        return 0
    return max(0, current_seats_used - plan.seats)
