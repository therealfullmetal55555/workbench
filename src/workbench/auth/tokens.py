"""
Access tokens.

Fifteen minutes, HS256, and a deliberate refusal to be clever: no refresh inside
the token, no rolling expiry, no server-side session. The token says who you are
and which org you were looking at when it was minted, and then it expires.

Two claims are load-bearing:

  `org` — the organisation the token acts on. An access token that just named a
    user would let a tab opened for Acme act on Beta after the user switched,
    because the browser keeps sending the old header. Binding the org means the
    token is wrong, not merely insufficient, and `POST /auth/refresh` issues a
    new one.

  `ver` — bumping it invalidates every access token the user holds. Without it,
    "log out everywhere" is a lie for up to fifteen minutes, which is exactly the
    window you care about when an account is compromised.

The cost of stateless tokens is that revocation is bounded by the lifetime. That
is the trade: a database round trip on every request to check a session table, or
at most one token lifetime of exposure. Fifteen minutes is the number because
it's long enough to be useful and short enough to be survivable.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt

from workbench.core.settings import get_settings

TokenType = Literal["access"]

TOKEN_TYPE = "access"
ISSUER = "workbench"
AUDIENCE = "workbench-api"

# Tokens are validated with a small amount of slack. Two machines with NTP drift
# of a few seconds otherwise reject tokens that were just minted by the other —
# a failure that only shows up under load, on one host, and is blamed on the
# load balancer for a week.
CLOCK_SKEW_SECONDS = 30


class TokenError(Exception):
    """Raised for any token that should not be trusted. Never carries the reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class AccessToken:
    value: str
    expires_at: datetime
    token_id: str

    @property
    def expires_in(self) -> int:
        return max(0, int((self.expires_at - datetime.now(UTC)).total_seconds()))


def mint_access_token(
    *,
    user_id: uuid.UUID | str,
    org_id: uuid.UUID | str | None = None,
    token_version: int = 0,
    is_staff: bool = False,
    impersonation_id: uuid.UUID | str | None = None,
    minutes: int | None = None,
) -> AccessToken:
    settings = get_settings()
    lifetime = timedelta(minutes=minutes or settings.access_token_minutes)
    now = datetime.now(UTC)
    expires_at = now + lifetime
    token_id = uuid.uuid4().hex

    claims: dict[str, Any] = {
        "sub": str(user_id),
        "org": str(org_id) if org_id else None,
        "typ": TOKEN_TYPE,
        "ver": token_version,
        "jti": token_id,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    # Staff and impersonation are claims rather than database lookups because
    # they change the *shape* of a request, not its authorisation: an org role
    # is still resolved per request from the membership table. If that read
    # disagrees with this token, the database wins — see `resolve_principal`.
    if is_staff:
        claims["staff"] = True
    if impersonation_id:
        claims["imp"] = str(impersonation_id)

    value = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return AccessToken(value=value, expires_at=expires_at, token_id=token_id)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Verify and return the claims. Raises `TokenError` for anything else.

    One exit, one exception type, and no detail: a client that can tell the
    difference between "expired" and "bad signature" is a client that can probe
    your key material a bit at a time.
    """
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iat", "sub", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid") from exc

    if claims.get("typ") != TOKEN_TYPE:
        # A token minted for another purpose (a reset link, a download URL) must
        # not authenticate a session. Cross-use of token types is how a
        # password-reset link ends up as an API credential.
        raise TokenError("wrong_type")

    return claims


def claims_org_id(claims: dict[str, Any]) -> uuid.UUID | None:
    raw = claims.get("org")
    if not raw:
        return None
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError) as exc:
        raise TokenError("bad_org_claim") from exc


def claims_user_id(claims: dict[str, Any]) -> uuid.UUID:
    try:
        return uuid.UUID(str(claims["sub"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise TokenError("bad_subject") from exc


def seconds_until_expiry(claims: dict[str, Any]) -> int:
    exp = claims.get("exp")
    if not exp:
        return 0
    return max(0, int(exp - time.time()))
