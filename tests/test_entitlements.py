"""
Entitlement resolution.

The module is a pure function of (subscription, overrides, usage), so none of
this needs a database. That's the reason the design is what it is: the code that
decides whether a customer gets a feature should be the easiest code in the
system to test, because it's the code whose bugs turn into refunds.
"""

from __future__ import annotations

import pytest

from workbench.billing.entitlements import (
    FEATURE_ATTRIBUTES,
    GRANTING_STATUSES,
    OVERRIDABLE,
    READ_GRACE_DAYS,
    Entitlements,
    FeatureNotIncluded,
    QuotaExceeded,
    Subscription,
    Usage,
    _sanitise_overrides,
    all_plans,
    resolve_from_orm,
)
from workbench.billing.plans import CATALOGUE, Plan, seat_downgrade_blockers

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_no_subscription_resolves_to_free():
    ent = Entitlements.resolve()
    assert ent.plan.code == "free"
    assert not ent.allows("sso")
    assert ent.remaining("seats") == 3


def test_active_team_subscription_resolves_to_team():
    ent = Entitlements.resolve(subscription=Subscription(plan_code="team", status="active"))
    assert ent.plan.code == "team"
    assert ent.limit_for("seats") == 25
    assert not ent.allows("sso")


def test_enterprise_is_unlimited_where_it_says_it_is():
    ent = Entitlements.resolve(subscription=Subscription(plan_code="enterprise", status="active"))
    assert ent.limit_for("seats") is None
    assert ent.remaining("seats") is None
    assert ent.allows("sso")
    assert ent.usage_ratio == 0.0, "an unlimited plan has no meaningful ratio"


@pytest.mark.parametrize("status", sorted(GRANTING_STATUSES))
def test_granting_statuses_keep_the_paid_plan(status):
    ent = Entitlements.resolve(subscription=Subscription(plan_code="team", status=status))
    assert ent.plan.code == "team"
    assert not ent.is_read_only


@pytest.mark.parametrize("status", ["unpaid", "canceled", "incomplete"])
def test_non_granting_statuses_keep_limits_but_become_read_only(status):
    """
    Deliberate: limits stay at the paid tier during the grace period.

    Dropping a customer to free limits the moment a payment fails would lock
    them out of their own data on the day they most need to export it. They lose
    the ability to write, not the ability to read.
    """
    ent = Entitlements.resolve(subscription=Subscription(plan_code="team", status=status))
    assert ent.is_read_only
    assert ent.plan.code == "team"
    assert ent.read_grace_days() == READ_GRACE_DAYS[status]


def test_a_free_org_is_never_read_only():
    """Free orgs have no subscription to lapse. Marking them read-only locks out signups."""
    assert not Entitlements.resolve().is_read_only


def test_unknown_plan_code_falls_back_to_free_not_unlimited():
    """The failure mode of a typo must be 'too little access', never 'too much'."""
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="enterprise-v2", status="active")
    )
    assert ent.plan.code == "free"
    assert not ent.allows("sso")


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------


def test_override_wins_over_the_plan():
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        overrides={"sso": True},
    )
    assert ent.allows("sso")
    assert ent.plan.code == "team", "an override must not rewrite the plan code"


def test_override_can_raise_a_limit():
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="free", status="active"),
        overrides={"seats": 50, "monthly_requests": 500_000},
    )
    assert ent.limit_for("seats") == 50
    assert ent.limit_for("requests_this_month") == 500_000


def test_override_can_make_a_limit_unlimited():
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        overrides={"monthly_requests": None},
    )
    assert ent.limit_for("requests_this_month") is None


def test_override_can_remove_a_feature():
    """Sales giveth, and sales taketh away — a stripped-down deal must be expressible."""
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="enterprise", status="active"),
        overrides={"sso": False},
    )
    assert not ent.allows("sso")


def test_unknown_override_keys_are_dropped_not_stored():
    ent = Entitlements.resolve(overrides={"sso": True, "unlimited_everything": True})
    assert ent.overrides == {"sso": True}


def test_overrides_survive_a_lapsed_subscription():
    """
    A signed contract mid-migration shouldn't lose its terms to a missed webhook.
    """
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="enterprise", status="canceled"),
        overrides={"monthly_requests": 10_000_000},
    )
    assert ent.limit_for("requests_this_month") == 10_000_000


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"seats": 10}, {"seats": 10}),
        ({"seats": -5}, {}),
        ({"seats": "ten"}, {}),
        ({"seats": None}, {"seats": None}),
        ({"sso": "yes"}, {"sso": True}),
        ({"sso": 0}, {"sso": False}),
        ({"overage": "soft"}, {"overage": "soft"}),
        ({"overage": "whatever"}, {}),
        ({"made_up": 1}, {}),
    ],
)
def test_sanitiser_accepts_only_what_it_should(raw, expected):
    assert _sanitise_overrides(raw) == expected


def test_overridable_set_matches_the_plan_fields():
    """A name in OVERRIDABLE that isn't a plan field would be silently dropped later."""
    plan_fields = set(Plan.__dataclass_fields__)
    unknown = OVERRIDABLE - plan_fields
    assert not unknown, f"OVERRIDABLE names fields that don't exist: {unknown}"


# ---------------------------------------------------------------------------
# Quotas
# ---------------------------------------------------------------------------


def test_free_plan_hard_stops():
    ent = Entitlements.resolve(usage=Usage(seats=3))
    with pytest.raises(QuotaExceeded) as exc:
        ent.require("seats")
    assert exc.value.limit == 3
    assert exc.value.used == 3
    assert exc.value.plan == "free"


def test_paid_plan_soft_overage_passes_through():
    """
    Cutting off a paying customer mid-month is a refund conversation, not an
    upsell. They keep working and get billed.
    """
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        usage=Usage(requests_this_month=100_001),
    )
    ent.require("requests_this_month")  # must not raise
    assert ent.overage_units("requests_this_month") == 1
    assert ent.is_over_quota


def test_unlimited_plan_never_raises():
    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="enterprise", status="active"),
        usage=Usage(requests_this_month=10**12, seats=10_000),
    )
    ent.require("requests_this_month")
    ent.require("seats")
    assert ent.overage_units("requests_this_month") == 0


def test_remaining_never_goes_negative():
    ent = Entitlements.resolve(usage=Usage(requests_this_month=9_999))
    assert ent.remaining("requests_this_month") == 0


def test_would_exceed_accounts_for_the_amount_being_added():
    ent = Entitlements.resolve(usage=Usage(seats=2))
    assert not ent.would_exceed("seats", 1)
    assert ent.would_exceed("seats", 2)


def test_near_quota_band():
    near = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        usage=Usage(requests_this_month=85_000),
    )
    assert near.is_near_quota
    assert not near.is_over_quota

    fine = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        usage=Usage(requests_this_month=1_000),
    )
    assert not fine.is_near_quota


def test_unknown_entitlement_is_a_keyerror_not_a_silent_false():
    """A typo in a route must fail loudly rather than deny a paying customer."""
    ent = Entitlements.resolve()
    with pytest.raises(KeyError):
        ent.limit_for("requests_per_millisecond")


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


def test_unknown_features_are_denied_not_allowed():
    ent = Entitlements.resolve(subscription=Subscription(plan_code="enterprise", status="active"))
    assert not ent.allows("time_travel")
    with pytest.raises(FeatureNotIncluded):
        ent.require_feature("time_travel")


def test_require_feature_names_the_plan_in_the_error():
    ent = Entitlements.resolve(usage=Usage())
    with pytest.raises(FeatureNotIncluded) as exc:
        ent.require_feature("sso")
    assert "free" in str(exc.value)


def test_audit_export_maps_to_the_audit_log_entitlement():
    assert FEATURE_ATTRIBUTES["audit_export"] == FEATURE_ATTRIBUTES["audit_log"]


# ---------------------------------------------------------------------------
# The payload the frontend gets
# ---------------------------------------------------------------------------


def test_to_dict_is_json_serialisable_and_complete():
    import json

    ent = Entitlements.resolve(
        subscription=Subscription(plan_code="team", status="active"),
        usage=Usage(seats=4, requests_this_month=1_234),
    )
    payload = json.loads(json.dumps(ent.to_dict(), default=str))

    assert payload["plan"]["code"] == "team"
    assert payload["usage"]["requests_this_month"] == 1_234
    assert payload["remaining"]["seats"] == 21
    assert "sso" not in payload["features"]
    assert payload["subscription"]["status"] == "active"
    assert payload["is_read_only"] is False


def test_to_dict_lists_override_keys_so_support_can_see_them():
    ent = Entitlements.resolve(overrides={"seats": 50, "sso": True})
    assert ent.to_dict()["overrides"] == ["seats", "sso"]


# ---------------------------------------------------------------------------
# ORM adapter
# ---------------------------------------------------------------------------


class FakeOrg:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}


class FakeSubscription:
    def __init__(self, plan_code="team", status="active", **kw):
        self.plan_code = plan_code
        self.status = status
        self.current_period_end = kw.get("current_period_end")
        self.cancel_at_period_end = kw.get("cancel_at_period_end", False)
        self.quantity = kw.get("quantity", 1)
        self.provider = kw.get("provider", "stripe")


def test_resolve_from_orm_maps_rows_to_entitlements():
    ent = resolve_from_orm(
        FakeOrg({"sso": True}),
        FakeSubscription("team", "active"),
        requests_this_month=42,
    )
    assert ent.plan.code == "team"
    assert ent.allows("sso")
    assert ent.usage.requests_this_month == 42


def test_resolve_from_orm_handles_an_org_with_no_subscription():
    ent = resolve_from_orm(FakeOrg(), None)
    assert ent.plan.code == "free"
    assert ent.subscription is None


# ---------------------------------------------------------------------------
# The catalogue itself
# ---------------------------------------------------------------------------


def test_every_plan_is_reachable_from_all_plans():
    codes = {plan["code"] for plan in all_plans()}
    assert codes == set(CATALOGUE)


def test_plans_are_ordered_free_team_enterprise():
    assert list(CATALOGUE) == ["free", "team", "enterprise"]


def test_limits_increase_with_price():
    free, team, enterprise = CATALOGUE["free"], CATALOGUE["team"], CATALOGUE["enterprise"]

    assert free.seats < team.seats
    # None means unlimited, so it's "greater" than any number by definition.
    assert enterprise.seats is None and enterprise.is_unlimited
    assert free.monthly_requests < team.monthly_requests
    assert team.monthly_requests < (enterprise.monthly_requests or float("inf"))
    assert free.retention_days < team.retention_days < enterprise.retention_days
    assert free.api_rate_limit_per_minute < team.api_rate_limit_per_minute


def test_downgrade_blockers_are_counted_before_they_bite():
    assert seat_downgrade_blockers(CATALOGUE["free"], current_seats_used=10) == 7
    assert seat_downgrade_blockers(CATALOGUE["free"], current_seats_used=2) == 0
    assert seat_downgrade_blockers(CATALOGUE["enterprise"], current_seats_used=10_000) == 0


def test_no_free_plan_offers_an_enterprise_feature():
    free = CATALOGUE["free"]
    for feature in ("sso", "priority_support", "custom_domain"):
        assert not getattr(free, feature), f"{feature} is on the free plan — that's a pricing bug"


def test_plan_construction_rejects_nonsense():
    with pytest.raises(ValueError, match="seats"):
        Plan(
            code="free",
            name="X",
            description="",
            seats=0,
            monthly_requests=1,
            retention_days=1,
            overage="hard",
        )
    with pytest.raises(ValueError, match="retention"):
        Plan(
            code="free",
            name="X",
            description="",
            seats=1,
            monthly_requests=1,
            retention_days=0,
            overage="hard",
        )
