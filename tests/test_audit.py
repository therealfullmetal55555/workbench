"""
Audit log behaviour.

The redaction tests matter most: the log is append-only, so a secret that gets
written here cannot be removed. The only defence is not writing it, and the only
way to trust that is to test it.
"""

from __future__ import annotations

import pytest

from workbench.audit.log import AuditError, _infer_actor_kind, _label_for, write_audit
from workbench.audit.models import EVENT_KINDS, SENSITIVE_KEYS, redact

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_password_hashes_never_reach_the_log():
    result = redact({"email": "owner@acme.test", "password_hash": "$argon2id$v=19$..."})
    assert result["email"] == "owner@acme.test"
    assert result["password_hash"] == "«redacted»"


def test_redaction_is_recursive():
    """Secrets hide in nested payloads more often than they appear at the top."""
    result = redact(
        {
            "account": {"stripe_secret_key": "sk_live_abc", "plan": "team"},
            "keys": [{"secret": "shh", "name": "prod"}, {"name": "dev"}],
        }
    )
    assert result["account"]["stripe_secret_key"] == "«redacted»"
    assert result["account"]["plan"] == "team"
    assert result["keys"][0]["secret"] == "«redacted»"
    assert result["keys"][0]["name"] == "prod"
    assert result["keys"][1]["name"] == "dev"


def test_redaction_is_case_insensitive():
    assert redact({"Password": "hunter2"})["Password"] == "«redacted»"
    assert redact({"API_KEY": "wb_live_x"})["API_KEY"] == "«redacted»"


def test_redaction_preserves_none_and_empty():
    assert redact(None) is None
    assert redact({}) == {}


def test_sensitive_key_list_covers_the_obvious_ones():
    for key in ("password", "token", "secret", "api_key", "card_number", "cvc", "refresh_token"):
        assert key in SENSITIVE_KEYS, f"{key} is not redacted"


def test_redaction_does_not_mutate_the_input():
    original = {"token": "abc", "plan": "team"}
    redact(original)
    assert original == {"token": "abc", "plan": "team"}


# ---------------------------------------------------------------------------
# Event names
# ---------------------------------------------------------------------------


def test_event_names_are_unique_and_well_formed():
    assert len(EVENT_KINDS) == len(set(EVENT_KINDS))
    for event in EVENT_KINDS:
        resource, _, verb = event.partition(".")
        assert resource and verb, f"'{event}' is not <resource>.<verb>"
        assert verb.islower(), f"'{event}' should be lower case"


def test_every_billing_event_the_product_emits_is_declared():
    for event in ("billing.plan_changed", "billing.payment_failed", "member.role_changed"):
        assert event in EVENT_KINDS


async def test_unknown_event_names_are_rejected_loudly():
    """
    A typo'd event name is a filter that silently never matches — a dashboard
    that shows nothing, discovered months later by a customer's auditor.
    """
    with pytest.raises(AuditError, match="unknown audit event"):
        await write_audit(None, event="billing.plan_chaged")  # type: ignore[arg-type]


async def test_staff_actions_require_a_reason():
    with pytest.raises(AuditError, match="reason"):
        await write_audit(None, event="staff.plan_overridden", actor_kind="staff")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Actor inference
# ---------------------------------------------------------------------------


class FakeUser:
    id = "11111111-1111-1111-1111-111111111111"
    email = "owner@acme.test"
    is_staff = False


class FakeStaff:
    id = "22222222-2222-2222-2222-222222222222"
    email = "staff@workbench.test"
    is_staff = True


class FakeApiKey:
    id = "33333333-3333-3333-3333-333333333333"
    prefix = "wb_live_abc123"


def test_actor_kind_is_inferred_from_the_object():
    assert _infer_actor_kind(FakeUser()) == "user"
    assert _infer_actor_kind(FakeStaff()) == "staff"
    assert _infer_actor_kind(FakeApiKey()) == "api_key"
    assert _infer_actor_kind(None) == "system"


def test_labels_prefer_something_a_human_recognises():
    class Org:
        id = "44444444-4444-4444-4444-444444444444"
        name = "Acme Corporation"

    class Nameless:
        id = "55555555-5555-5555-5555-555555555555"

    assert _label_for(Org()) == "Acme Corporation"
    assert _label_for(Nameless()) is None
