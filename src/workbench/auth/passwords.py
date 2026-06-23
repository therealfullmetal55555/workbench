"""
Password and token hashing.

Argon2id with the library's defaults. Not bcrypt (72-byte truncation surprises
people every year), not scrypt (fine, but argon2id is the current recommendation
and the bindings are better maintained), and definitely not a hand-rolled loop.

The parameters below are explicit rather than defaulted so that the cost is a
visible decision. When you raise them, old hashes keep working — the parameters
are encoded in the hash string — and `needs_rehash()` tells you which ones to
upgrade on next login.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

from workbench.core.settings import get_settings

# ~50ms on a modest 2026 core, which is the point: fast enough for a login form,
# slow enough that an offline attack on a leaked dump is expensive.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=1,  # CI runners and small containers don't have 4 cores
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    needs_rehash: bool = False
    reason: str | None = None


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> PasswordCheck:
    """
    Never raises. A malformed hash in the database is a data problem, not a
    request-level error, and it must not surface as a 500 that tells an attacker
    which account has a broken row.
    """
    try:
        _hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return PasswordCheck(ok=False, reason="mismatch")
    except (VerificationError, InvalidHashError):
        return PasswordCheck(ok=False, reason="invalid_hash")
    except Exception:  # noqa: BLE001
        return PasswordCheck(ok=False, reason="error")

    return PasswordCheck(ok=True, needs_rehash=_hasher.check_needs_rehash(stored_hash))


_dummy_hash: str | None = None


def consume_dummy_verify(password: str) -> None:
    """
    Do the work of a real verification and throw the result away.

    Called when the account doesn't exist, so that a login attempt against an
    unknown address costs what a real one costs. Without it, `time curl` against
    the login endpoint answers "does this customer have an account" — which is
    the question every credential-stuffing list is built from.

    The hash is generated on first use rather than at import: it's a real argon2
    hash at the configured cost, so doing it at import would add 50ms to every
    process start, including `--help`.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(32))
    verify_password(password, _dummy_hash)


def password_problems(
    password: str, *, email: str | None = None, name: str | None = None
) -> list[str]:
    """
    Return the reasons a password is unacceptable. Empty list means it's fine.

    Deliberately no composition rules. "One uppercase, one digit, one symbol"
    produces `Password1!` and nothing else. Length plus a check against the
    obvious guesses does more, and doesn't make people write it on a sticky note.

    Two things are refused that the rules above do not cover, and both are about
    guessability rather than shape: a common password repeated until it is long
    enough to clear the floor, and a string with no letters in it at all. An
    all-lowercase passphrase is accepted, on purpose — see `tests/test_credentials.py`,
    where that decision is written down so the next person does not "fix" it.
    """
    settings = get_settings()
    problems: list[str] = []

    if len(password) < settings.password_min_length:
        problems.append(f"must be at least {settings.password_min_length} characters")

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        problems.append("is one of the most commonly used passwords")

    # A common password repeated until it clears the length floor. `password`
    # fails the check above; `passwordpassword` walks past it, and it is in the
    # first hundred guesses of every tool. Collapsing the repeat catches the whole
    # family without banning the substring — "secret" appears in this list and
    # "secretsanta-rules-2026" is a perfectly good passphrase.
    for word in COMMON_PASSWORDS:
        if len(word) >= 6 and len(lowered) >= 2 * len(word) and lowered.replace(word, "") == "":
            problems.append("is one of the most commonly used passwords, repeated")
            break

    # No letters at all. This is not a composition rule — nothing here requires
    # an uppercase letter or a symbol, because those rules produce `Password1!`
    # and nothing else. It is the observation that a long digits-only string is a
    # date, a phone number or a PIN, and those are the guesses that actually
    # succeed in practice.
    if not any(character.isalpha() for character in password):
        problems.append("must contain at least one letter")

    # Contains the email local part or the user's name — the first thing any
    # password-guessing tool tries.
    for fragment in (email, name):
        if not fragment:
            continue
        for part in fragment.lower().replace("@", " ").replace(".", " ").split():
            if len(part) >= 3 and part in lowered:
                problems.append(f"must not contain '{part}'")
                break

    if len(set(password)) < 4:
        problems.append("has too few distinct characters")

    return problems


def validate_password(password: str, *, email: str | None = None, name: str | None = None) -> None:
    problems = password_problems(password, email=email, name=name)
    if problems:
        raise ValueError("; ".join(problems))


# ---------------------------------------------------------------------------
# Opaque tokens: refresh tokens, invitations, password resets, API key secrets
# ---------------------------------------------------------------------------


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """
    SHA-256, not argon2, and that's deliberate.

    These tokens are 256 bits of `secrets.token_urlsafe` — there is nothing to
    brute-force, so a slow KDF buys nothing and costs a hash per request. Passwords
    are the opposite case: low entropy, so the work factor is the defence.

    The pepper matters anyway: if the database leaks without the app config, the
    stored hashes are inert.
    """
    pepper = get_settings().jwt_secret.encode()
    return hashlib.sha256(pepper + token.encode()).hexdigest()


def verify_token(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), stored_hash)


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApiKeyMaterial:
    plaintext: str  # shown to the user exactly once
    prefix: str  # stored in the clear, indexed, used for lookup
    secret_hash: str  # stored, never returned


def generate_api_key(prefix: str | None = None, environment: str = "test") -> ApiKeyMaterial:
    """
    Shape: wb_live_8f3a1c_<43 chars>

    The `live`/`test` segment is there so a key pasted into a GitHub issue is
    immediately identifiable, and so a leaked test key doesn't look like a
    production incident. Same reasoning as Stripe's, because it's right.
    """
    prefix = prefix or get_settings().api_key_prefix
    env_tag = "live" if environment == "production" else "test"
    lookup = secrets.token_hex(3)  # 6 chars, enough to be unique per org
    secret = secrets.token_urlsafe(32)

    return ApiKeyMaterial(
        plaintext=f"{prefix}_{env_tag}_{lookup}_{secret}",
        prefix=f"{prefix}_{env_tag}_{lookup}",
        secret_hash=hash_token(secret),
    )


def parse_api_key(value: str) -> tuple[str, str] | None:
    """
    Split a presented key into (prefix, secret). Returns None if malformed.

    The split is bounded at three separators, and that is not a style choice.
    `token_urlsafe` produces `-` and `_` characters, so roughly half of all
    generated secrets contain an underscore — and an unbounded `split("_")`
    turns those keys into five or six parts, fails the length check, and hands
    the customer a 401 on a key that was minted thirty seconds earlier. It is
    also invisible in review: the keys in the fixtures happened to be clean, the
    parser looked obviously correct, and the bug only shows up on the keys that
    contain the separator. Every third key in production, intermittently.

    Splitting from the left is safe because the secret is the last field and may
    contain anything. The lookup is the third, and it is hex.
    """
    parts = value.split("_", 3)
    if len(parts) != 4:
        return None
    prefix, env_tag, lookup, secret = parts
    if env_tag not in {"live", "test"} or not lookup or not secret:
        return None
    return f"{prefix}_{env_tag}_{lookup}", secret


# A short list beats a dependency here. Anything longer belongs in a breach
# corpus you actually maintain; this catches the passwords that show up in every
# credential-stuffing list.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd",
        "p@ssw0rd",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "letmein",
        "welcome",
        "welcome1",
        "admin",
        "administrator",
        "root",
        "toor",
        "changeme",
        "secret",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "abc123",
        "111111",
        "000000",
        "zaq12wsx",
        "1q2w3e4r",
        "qazwsx",
        "trustno1",
        "starwars",
        "master",
        "shadow",
        "superman",
        "michael",
        "workbench",
        "workbench123",
        "test1234",
        "devpassword",
    }
)
