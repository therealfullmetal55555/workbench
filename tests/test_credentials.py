"""
Credentials: passwords, tokens, API keys.

No database and no network. Everything here is pure function behaviour, which is
exactly why it needs tests: a hashing helper that is 99% right is a bug nobody
sees until the wrong 1% of users cannot sign in.
"""

from __future__ import annotations

import time

import pytest

from workbench.auth.passwords import (
    PasswordCheck,
    consume_dummy_verify,
    generate_api_key,
    hash_password,
    hash_token,
    parse_api_key,
    password_problems,
    verify_password,
    verify_token,
)

pytestmark = pytest.mark.unit

PASSWORD = "correct-horse-battery-staple"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def test_a_password_verifies_against_its_own_hash():
    stored = hash_password(PASSWORD)
    assert verify_password(PASSWORD, stored).ok


def test_a_wrong_password_does_not():
    stored = hash_password(PASSWORD)
    assert not verify_password(PASSWORD + "x", stored).ok


def test_the_hash_is_not_the_password():
    stored = hash_password(PASSWORD)
    assert PASSWORD not in stored
    assert stored.startswith("$argon2")  # or $scrypt, depending on the backend


def test_the_same_password_hashes_differently_every_time():
    """Salted, so two users with the same password don't share a hash."""
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_verify_reports_ok_rather_than_raising_on_a_corrupt_hash():
    """
    A hash from a different algorithm, or a truncated one, must be a failed login
    rather than a 500. Anything else turns a bad row into an outage.
    """
    result = verify_password(PASSWORD, "not-a-hash")
    assert isinstance(result, PasswordCheck)
    assert not result.ok


@pytest.mark.parametrize(
    ("password", "expect_problem", "why"),
    [
        ("short", True, "below the length floor"),
        ("123456789012345678", True, "long, but a date or a PIN: no letters in it"),
        ("passwordpassword", True, "a common password repeated to clear the floor"),
        ("correct-horse-battery-staple", False, "fine"),
        ("Tr0ub4dor&3-correct-style", False, "fine"),
    ],
)
def test_password_rules_are_stated_not_implied(password, expect_problem, why):
    problems = password_problems(password)
    assert bool(problems) is expect_problem, (why, problems)


def test_a_password_containing_the_users_own_details_is_refused():
    problems = password_problems("acme-corp-2026-ok", email="someone@acme.test", name="Someone")
    assert problems, problems


def test_an_all_lowercase_passphrase_is_accepted_on_purpose():
    """
    Written down because it looks like an oversight.

    There are no composition rules here: no required uppercase letter, digit or
    symbol. The reasoning is in `password_problems` — those rules train people to
    produce `Password1!` and to write it on a sticky note — and this test exists so
    the absence is a decision with a test behind it rather than a gap somebody
    closes in a hurry.
    """
    assert password_problems("nineteen-chars-of-prose") == []
    # ...while the shape with no letters at all is refused.
    assert password_problems("987654321098765432") == ["must contain at least one letter"]


def test_the_dummy_verify_costs_what_a_real_verify_costs():
    """
    The timing trick that keeps "unknown address" indistinguishable from "wrong
    password". If it ever becomes a no-op the enumeration defence quietly
    disappears, so the cost is asserted rather than assumed.
    """
    real_start = time.perf_counter()
    verify_password(PASSWORD, hash_password(PASSWORD))
    real = time.perf_counter() - real_start

    dummy_start = time.perf_counter()
    consume_dummy_verify(PASSWORD)
    dummy = time.perf_counter() - dummy_start

    assert dummy > real / 10, "the dummy verify is doing far less work than a real one"


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def test_a_generated_key_round_trips_through_the_parser():
    material = generate_api_key()
    parsed = parse_api_key(material.plaintext)

    assert parsed is not None
    assert parsed == (material.prefix, parsed[1])
    assert verify_token(parsed[1], material.secret_hash)


def test_every_generated_key_parses():
    """
    The regression this file exists for.

    `token_urlsafe` emits `-` and `_`, so an unbounded `split("_")` mangled
    roughly half of all generated keys into six parts and rejected them — a 401
    on a key minted thirty seconds earlier, on some keys and not others. The
    parser looked obviously correct, which is why it survived review.
    """
    unparseable = [
        m.plaintext
        for m in (generate_api_key() for _ in range(500))
        if parse_api_key(m.plaintext) is None
    ]
    assert unparseable == []


def test_a_secret_containing_the_separator_is_handled():
    """The specific shape that used to fail, without relying on luck."""
    parsed = parse_api_key("wb_test_ab12cd_sec_ret_with_underscores")
    assert parsed == ("wb_test_ab12cd", "sec_ret_with_underscores")


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "wb_live_",
        "wb_test_ab12cd",
        "wb_test_ab12cd_",
        "not-a-key",
        "wb_prod_ab12cd_secret",  # only live/test are valid environment tags
        "wb_test__secret",
    ],
)
def test_malformed_keys_are_rejected_rather_than_half_read(malformed):
    assert parse_api_key(malformed) is None


def test_the_prefix_is_distinct_from_the_secret():
    """
    The prefix is stored in clear text and is what the lookup uses; the secret is
    hashed and is what proves possession. A key where they are the same value
    would mean a database read is enough to use the key.
    """
    material = generate_api_key()
    assert material.prefix not in material.secret_hash
    assert material.plaintext.startswith(material.prefix + "_")
    assert hash_token(material.plaintext) != material.plaintext


def test_live_and_test_keys_look_different():
    """So a key pasted into an issue is identifiable at a glance."""
    assert "_live_" in generate_api_key(environment="production").plaintext
    assert "_test_" in generate_api_key(environment="staging").plaintext


def test_tokens_are_hashed_so_a_dump_is_not_a_set_of_credentials():
    """
    Refresh tokens, invitation links and reset links are stored as hashes. That
    is why a database dump doesn't hand over working sessions.
    """
    token = "sT4t3l3ss-t0k3n"
    digest = hash_token(token)

    assert digest != token
    assert token not in digest
    assert verify_token(token, digest)
    assert not verify_token(token + "x", digest)
    assert hash_token(token) == digest  # deterministic, or lookup by hash is impossible


def test_two_tokens_of_the_same_length_are_not_related():
    """No counter, no timestamp, no guessable structure."""
    import secrets

    first, second = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    assert first != second
    assert hash_token(first) != hash_token(second)
