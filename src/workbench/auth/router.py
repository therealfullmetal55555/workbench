"""
Authentication endpoints.

Three things in this file are the whole point of it:

  * **Signup returns 202 for everyone.** The same status, the same body, the same
    timing, whether the address was free or taken. The difference goes in an
    email. Response codes that reveal whether a customer exists turn a leaked
    mailing list into a customer list.
  * **Login is rate limited by IP *and* by address.** Either alone is trivially
    defeated: a botnet rotates IPs, a single host tries one password against a
    thousand addresses. Both counters have to trip.
  * **Logout is idempotent.** 204 whether or not the token was live. Anything
    else makes a client that retries after a timeout look like an attacker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select

from workbench.api.deps import (
    PersonDep,
    PrincipalDep,
    Scope,
    SystemDep,
    client_ip,
    get_rate_limiter,
    get_settings_dep,
)
from workbench.api.errors import BadRequest, Conflict, InvalidToken, TooManyRequests, Unauthorized
from workbench.api.ratelimit import RateLimiter
from workbench.api.schemas import (
    LoginRequest,
    LogoutRequest,
    MembershipOut,
    MeOut,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    SignupRequest,
    TokenPair,
    UserOut,
)
from workbench.audit.log import write_audit
from workbench.auth import service
from workbench.auth.models import PasswordReset, RefreshToken, User
from workbench.auth.passwords import (
    consume_dummy_verify,
    hash_password,
    hash_token,
    password_problems,
)
from workbench.billing.plans import CATALOGUE
from workbench.core.models import uuid7
from workbench.core.permissions import permissions_for
from workbench.core.settings import Settings
from workbench.email.sender import enqueue
from workbench.tenancy.models import Membership, Organization

router = APIRouter(prefix="/auth", tags=["auth"])

# Deliberately generous for a human and useless for a script. Twenty tries a
# minute is more than anyone types and fewer than a credential-stuffing list
# needs; the address limit is tighter because that is the one that protects an
# individual account rather than the service.
LOGIN_PER_IP = 20
LOGIN_PER_EMAIL = 8
SIGNUP_PER_IP = 10
RESET_PER_EMAIL = 3

RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def _auth_error(exc: service.AuthError) -> Exception:
    """Map service refusals onto status codes. One place, so they stay consistent."""
    if exc.reason == "locked":
        return TooManyRequests(exc.message, retry_after=exc.retry_after or 900)
    if exc.reason in {"not_a_member", "empty_scopes"}:
        return BadRequest(exc.message)
    if exc.reason in {"invalid_slug", "slug_taken"}:
        # 409, not 400: nothing about the request is malformed — the name is fine
        # and it is simply in use. A client that shows "try another name" keys off
        # this, and `slug_taken` used to fall through to a 500.
        return Conflict(exc.message)
    if exc.reason in {"reuse_detected", "expired_refresh", "invalid_refresh"}:
        # A token-shaped problem type, so a client can tell "your credential is no
        # good, refresh or sign in again" from "you didn't send one" — which is
        # the difference between a retry loop and a redirect to the login screen.
        return InvalidToken(exc.message)
    return Unauthorized(exc.message)


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------


@router.post(
    "/signup",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create an account",
    description=(
        "Always returns 202 with the same body. Whether the address was free or "
        "already registered is not observable from the response — the difference "
        "arrives by email, and only the address's owner can read it."
    ),
)
async def signup(
    payload: SignupRequest,
    request: Request,
    scope: SystemDep,
    limiter: RateLimiterDep,
    settings: SettingsDep,
) -> dict[str, str]:
    ip = client_ip(request)
    decision = await limiter.check(f"signup:ip:{ip}", limit=SIGNUP_PER_IP, window_seconds=3600)
    if not decision.allowed:
        raise TooManyRequests(
            "too many accounts created from this address; try again later",
            retry_after=decision.reset_after,
        )

    user, org, created = await service.signup(
        scope.session,
        email=str(payload.email),
        password=payload.password,
        name=payload.name or "",
        org_name=payload.org_name,
        org_slug=payload.org_slug,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )

    if created and user is not None:
        token, token_hash = _new_token_pair()
        scope.session.add(
            PasswordReset(
                id=uuid7(),
                user_id=user.id,
                token_hash=token_hash,
                expires_at=PasswordReset.default_expiry(24 * 60),
                requested_ip=ip,
            )
        )
        enqueue(
            "verification",
            to=user.email,
            name=user.name,
            email=user.email,
            verify_url=f"{settings.app_base_url}/verify?token={token}",
            ttl_hours=24,
        )
    else:
        # Identical work, identical response, opposite email. This is the message
        # that tells a real customer somebody is trying to sign up as them —
        # which is useful to them and useless to an attacker.
        enqueue(
            "password_reset",
            to=str(payload.email),
            name="",
            reset_url=f"{settings.app_base_url}/reset",
            ttl_minutes=60,
            ip_address=ip,
        )

    return {
        "status": "accepted",
        "detail": "if that address can be used, a message is on its way",
    }


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=TokenPair, summary="Exchange credentials for a token pair")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    scope: SystemDep,
    limiter: RateLimiterDep,
) -> TokenPair:
    ip = client_ip(request)
    email = User.normalise_email(str(payload.email))

    for key, limit in ((f"login:ip:{ip}", LOGIN_PER_IP), (f"login:email:{email}", LOGIN_PER_EMAIL)):
        decision = await limiter.check(key, limit=limit, window_seconds=300)
        if not decision.allowed:
            raise TooManyRequests(
                "too many sign-in attempts; wait a moment and try again",
                retry_after=decision.reset_after,
            )

    try:
        result = await service.login(
            scope.session,
            email=email,
            password=payload.password,
            org_id=payload.org_id,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
    except service.AuthError as exc:
        raise _auth_error(exc) from exc

    # A correct password clears the address counter. Without this, a customer who
    # mistyped four times and then got it right is one typo away from a lockout.
    await limiter.reset(f"login:email:{email}")
    await limiter.reset(f"login:ip:{ip}")

    response.headers["X-Token-Expires-In"] = str(result.expires_in)
    return TokenPair(
        access_token=result.access.value,
        refresh_token=result.refresh_token,
        expires_in=result.expires_in,
    )


# ---------------------------------------------------------------------------
# Refresh and logout
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenPair, summary="Rotate a refresh token")
async def refresh(
    payload: RefreshRequest,
    request: Request,
    scope: SystemDep,
) -> TokenPair:
    try:
        result = await service.refresh(
            scope.session,
            token=payload.refresh_token,
            org_id=payload.org_id,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except service.AuthError as exc:
        raise _auth_error(exc) from exc

    return TokenPair(
        access_token=result.access.value,
        refresh_token=result.refresh_token,
        expires_in=result.expires_in,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the presented refresh chain",
)
async def logout(
    payload: LogoutRequest,
    request: Request,
    scope: SystemDep,
    principal: PrincipalDep,
) -> Response:
    # `principal` is optional here on purpose: a client that lost its access
    # token but still holds a refresh token must be able to log out, otherwise
    # the only way to revoke is to wait thirty days.
    user: User | None = principal.user
    if user is not None:
        pass
    elif payload.refresh_token:
        user = await _user_for_refresh_token(scope, payload.refresh_token)
        if user is None:
            # Never happened, or already revoked. Both are "logged out".
            return Response(status_code=status.HTTP_204_NO_CONTENT)
    else:
        raise Unauthorized("send an access token or the refresh token to revoke")

    await service.logout(
        scope.session,
        token=payload.refresh_token,
        user=user,
        all_devices=payload.all_devices,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _user_for_refresh_token(scope: Scope, token: str) -> User | None:
    """
    Find the owner of a refresh token without authenticating them.

    Logging out with an expired access token is legitimate — a stolen laptop, a
    cleared browser — so this reads the token by its hash and returns the user,
    without minting anything. It grants no access: the only thing this caller can
    do with the result is revoke.
    """
    from workbench.core.db import CREDENTIAL_SETTING, set_credential

    await set_credential(scope.session, CREDENTIAL_SETTING, hash_token(token))
    record = (
        await scope.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == hash_token(token))
        )
    ).scalar_one_or_none()
    if record is None:
        return None
    return (
        await scope.session.execute(select(User).where(User.id == record.user_id))
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Who am I
# ---------------------------------------------------------------------------


@router.get("/me", response_model=MeOut, summary="The caller and their memberships")
async def me(principal: PersonDep, scope: SystemDep) -> MeOut:
    """
    Everything a client needs to render its shell in one call.

    Memberships come back with the org's name and slug joined in, because the
    alternative is the client making N+1 requests to label an org switcher — and
    memberships are the one thing a user is allowed to see across orgs.
    """
    user = principal.user
    assert user is not None  # PersonDep guarantees a user, not a key

    rows = (
        await scope.session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.org_id)
            .where(Membership.user_id == user.id, Membership.suspended_at.is_(None))
            .order_by(Membership.joined_at)
        )
    ).all()

    memberships = [
        MembershipOut(
            org_id=org.id,
            org_slug=org.slug,
            org_name=org.name,
            role=membership.role,
            joined_at=membership.joined_at,
        )
        for membership, org in rows
    ]

    return MeOut(
        user=UserOut.model_validate(user),
        memberships=memberships,
        active_org_id=principal.org_id,
        permissions=sorted(permissions_for(principal.role or "")),
        impersonating=principal.is_impersonating,
    )


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT, summary="Change password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    principal: PersonDep,
    scope: SystemDep,
) -> Response:
    """
    Changing a password revokes every refresh chain the user has.

    That is the point of the endpoint in an incident: "I think someone has my
    password" has to mean something, and it has to mean it immediately. The
    fifteen-minute window on outstanding access tokens is the floor set by the
    token design and it is documented in `auth/tokens.py`.
    """
    user = principal.user
    assert user is not None  # PersonDep guarantees a user, not a key

    from workbench.auth.passwords import verify_password

    if user.password_hash is None:
        raise BadRequest("this account has no password to change")

    if not verify_password(payload.current_password, user.password_hash).ok:
        raise Unauthorized("the current password is incorrect")

    problems = password_problems(payload.new_password, email=user.email, name=user.name)
    if problems:
        raise BadRequest("; ".join(problems))

    before = user.password_hash
    user.password_hash = hash_password(payload.new_password)

    revoked = await service.revoke_family_for_user(
        scope.session, user_id=user.id, reason="password_changed"
    )

    await write_audit(
        scope.session,
        event="user.password_changed",
        actor=user,
        target=user,
        before={"password_hash": before[:12] + "…"},
        after={"password_hash": user.password_hash[:12] + "…", "sessions_revoked": revoked},
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/password/reset",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset",
)
async def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    scope: SystemDep,
    limiter: RateLimiterDep,
    settings: SettingsDep,
) -> dict[str, str]:
    """Same answer whether or not the address exists. See `signup` for the argument."""
    ip = client_ip(request)
    email = User.normalise_email(str(payload.email))

    decision = await limiter.check(
        f"reset:email:{email}", limit=RESET_PER_EMAIL, window_seconds=3600
    )
    if not decision.allowed:
        # This one *does* leak a little: three requests an hour and then silence
        # could tell an attacker the address exists. The alternative is unlimited
        # password-reset mail to any address, which is a worse problem and one
        # that reaches the customer's spam folder rather than their support desk.
        raise TooManyRequests(
            "a reset has already been requested for this address recently",
            retry_after=decision.reset_after,
        )

    from workbench.core.db import LOGIN_EMAIL_SETTING, set_credential

    await set_credential(scope.session, LOGIN_EMAIL_SETTING, email)
    user = (
        await scope.session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()

    if user is None:
        consume_dummy_verify("not-a-real-password")
        return {
            "status": "accepted",
            "detail": "if that address has an account, a message is on its way",
        }

    # Requesting a new link invalidates the outstanding ones. Otherwise a reset
    # link from three weeks ago still works, and "I requested a new one" is not
    # a way to un-share a link that went to the wrong inbox.
    live = (
        (
            await scope.session.execute(
                select(PasswordReset).where(
                    PasswordReset.user_id == user.id, PasswordReset.used_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    for record in live:
        record.used_at = datetime.now(UTC)

    token, token_hash = _new_token_pair()
    scope.session.add(
        PasswordReset(
            id=uuid7(),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=PasswordReset.default_expiry(60),
            requested_ip=ip,
        )
    )

    await write_audit(
        scope.session,
        event="user.password_reset_requested",
        actor=user,
        target=user,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
    )
    enqueue(
        "password_reset",
        to=user.email,
        name=user.name,
        reset_url=f"{settings.app_base_url}/reset?token={token}",
        ttl_minutes=60,
        ip_address=ip or "unknown",
    )
    return {
        "status": "accepted",
        "detail": "if that address has an account, a message is on its way",
    }


@router.post(
    "/password/reset/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Complete a password reset",
)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    request: Request,
    scope: SystemDep,
) -> Response:
    from workbench.core.db import CREDENTIAL_SETTING, set_credential

    await set_credential(scope.session, CREDENTIAL_SETTING, hash_token(payload.token))
    record = (
        await scope.session.execute(
            select(PasswordReset).where(PasswordReset.token_hash == hash_token(payload.token))
        )
    ).scalar_one_or_none()

    if record is None or not record.is_usable:
        # One message for unknown, used, and expired. Which one it was is useful
        # only to somebody guessing.
        raise BadRequest("this reset link is not valid any more; request a new one")

    user = (
        await scope.session.execute(select(User).where(User.id == record.user_id))
    ).scalar_one_or_none()
    if user is None:
        raise BadRequest("this reset link is not valid any more; request a new one")

    problems = password_problems(payload.new_password, email=user.email, name=user.name)
    if problems:
        raise BadRequest("; ".join(problems))

    await set_credential(scope.session, "app.current_user", str(user.id))
    user.password_hash = hash_password(payload.new_password)
    record.used_at = datetime.now(UTC)

    revoked = await service.revoke_family_for_user(
        scope.session, user_id=user.id, reason="password_reset"
    )

    await write_audit(
        scope.session,
        event="user.password_changed",
        actor=user,
        target=user,
        after={"via": "reset_link", "sessions_revoked": revoked},
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _new_token_pair() -> tuple[str, str]:
    """Returns `(plaintext, hash)`. Only the hash is stored."""
    import secrets

    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def plans_public() -> list[dict]:
    """The pricing page's data. Here rather than in a router because it needs nothing."""
    return [
        {
            "code": plan.code,
            "name": plan.name,
            "description": plan.description,
            "seats": plan.seats,
            "monthly_requests": plan.monthly_requests,
        }
        for plan in CATALOGUE.values()
    ]


__all__ = ["router"]
