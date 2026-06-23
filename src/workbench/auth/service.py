"""
Authentication, as functions that take a session.

The routers next door know about HTTP; this file knows about logins. The split
exists because "a rotated refresh token replayed later revokes the family" is a
rule about credentials, and it should be testable without a request object, a
rate limiter, or a status code.

Four flows live here:

    signup    — always the same answer, whether or not the address is taken
    login     — find, verify, throttle, mint
    refresh   — rotate, and treat reuse as the theft it is
    logout    — revoke this device, or every device

A note on where the tenant comes from. None of these flows has an organisation
to scope to until the middle of the call: signup creates one, login discovers
which ones exist, refresh is told. So they run in sessions with no tenant set,
and the policies that let them read what they need are the credential policies
in migration 0002 — `app.current_login_email`, `app.current_credential`. There is
no `bypass=True` anywhere in this file, and that is not a detail: the application
role cannot see more than the credential it presented.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from workbench.audit.log import write_audit
from workbench.auth.models import ApiKey, LoginAttempt, RefreshToken, User
from workbench.auth.passwords import (
    consume_dummy_verify,
    hash_password,
    hash_token,
    password_problems,
    verify_password,
)
from workbench.auth.tokens import AccessToken, mint_access_token
from workbench.core.db import (
    ACTOR_SETTING,
    CREDENTIAL_SETTING,
    LOGIN_EMAIL_SETTING,
    commit_evidence,
    set_credential,
)
from workbench.core.models import uuid7
from workbench.core.settings import get_settings
from workbench.tenancy.models import Membership, Organization

log = logging.getLogger(__name__)


class AuthError(Exception):
    """Any refusal from this module. The router maps it to a status code."""

    def __init__(self, reason: str, message: str, *, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.retry_after = retry_after


@dataclass(slots=True)
class AuthResult:
    user: User
    access: AccessToken
    refresh_token: str
    org_id: uuid.UUID | None
    role: str | None

    @property
    def expires_in(self) -> int:
        return self.access.expires_in


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------


async def signup(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    name: str = "",
    org_name: str | None = None,
    org_slug: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User | None, Organization | None, bool]:
    """
    Create a user (and, usually, their first org).

    Returns `(user, org, created)`. When the address is already registered this
    returns `(None, None, False)` — **and the caller must not say so**. The route
    response is identical either way; the difference is which email gets sent,
    which is the only place the distinction is allowed to appear.

    The password is validated *before* the existence check, so a weak password on
    a taken address still fails validation. Otherwise "that password isn't good
    enough" would be a signal that the address was free.
    """
    normalised = User.normalise_email(email)

    problems = password_problems(password, email=normalised, name=name)
    if problems:
        raise AuthError("weak_password", "; ".join(problems))

    user_id = uuid7()
    # Both settings are written before anything is read. `users_login_lookup`
    # answers "is this address in use", and it is scoped to exactly this one
    # address — signup cannot discover anybody else's account.
    await set_credential(session, LOGIN_EMAIL_SETTING, normalised)
    await set_credential(session, "app.current_user", str(user_id))

    existing = (
        await session.execute(select(User).where(func.lower(User.email) == normalised))
    ).scalar_one_or_none()
    if existing is not None:
        log.info(
            "signup for an address that already exists", extra={"email_hash": _mask(normalised)}
        )
        return None, None, False

    user = User(
        id=user_id,
        email=normalised,
        name=name,
        password_hash=hash_password(password),
    )
    session.add(user)
    await session.flush()

    org: Organization | None = None
    if org_name:
        org = await create_organization(
            session,
            name=org_name,
            slug=org_slug,
            owner=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    await write_audit(
        session,
        event="user.signed_up",
        actor=user,
        org_id=org.id if org else None,
        target=user,
        after={"email": normalised, "org_id": str(org.id) if org else None},
        ip_address=ip_address,
        user_agent=user_agent,
    )
    # Note what is *not* written: no login event, no refresh token. Signing up
    # sends a verification email; the session starts at login. It's one extra
    # round trip for a legitimate user and it's the price of the identical
    # response above — which is worth paying, because the alternative tells
    # anyone with a word list which of your customers are registered.
    return user, org, True


async def create_organization(
    session: AsyncSession,
    *,
    name: str,
    slug: str | None = None,
    owner: User,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Organization:
    """
    Create an org and its first membership, in this transaction.

    The membership is not optional and not deferred. An org with no owner is an
    org nobody can administer — support ticket, manual SQL, and a row that exists
    only because a request failed halfway. Both rows commit together or neither.

    The tenant is set to the new org *before* inserting the membership, because
    `memberships` has the standard tenant policy and the insert has to satisfy
    it. Setting it here rather than trusting a caller is why this function takes
    the session rather than being a method on `User`.
    """
    from workbench.core.db import set_tenant

    base_slug = slug or Organization.slugify(name)
    org_id = uuid7()

    # The tenant is bound *before* the insert, not after, and that ordering is
    # load-bearing.
    #
    # Postgres applies the SELECT policies to the row an `INSERT ... RETURNING`
    # returns, and SQLAlchemy always returns on an ORM insert (it needs the
    # server-generated timestamps back). A brand-new organisation satisfies
    # `organizations_insert_by_creator` — the insert is allowed — but it is not
    # yet `app.current_org` and has no membership, so `organizations_member_read`
    # rejects the row being handed back. The error is "new row violates row-level
    # security policy", which points at the insert and is really about the read.
    #
    # Binding the tenant first fixes both halves: the returning row matches
    # `id = current_org`, and the membership below is inserted with the tenant
    # already in place, as its own policy requires.
    await set_tenant(session, org_id, actor_id=owner.id)

    try:
        org = await _insert_org(session, org_id=org_id, name=name, base_slug=base_slug)
    except ValueError as exc:  # reserved slug, from the model's validator
        raise AuthError("invalid_slug", str(exc)) from exc

    session.add(Membership(id=uuid7(), org_id=org.id, user_id=owner.id, role="owner"))
    await session.flush()

    await write_audit(
        session,
        event="org.created",
        actor=owner,
        target=org,
        after={"name": org.name, "slug": org.slug},
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return org


async def _insert_org(
    session: AsyncSession, *, org_id: uuid.UUID, name: str, base_slug: str
) -> Organization:
    """
    Insert the org, resolving a slug collision by retrying instead of by checking.

    The obvious version of this — `SELECT` the slug, see it is free, then
    `INSERT` — is a race, and not a theoretical one: two signups with the same
    company name arrive close enough together, both requests see `acme` free,
    both insert, one gets a unique violation and a 500 on the first screen of the
    product. The unique index is the only thing that can actually decide this, so
    the insert is the check.

    Each attempt runs in a SAVEPOINT. That detail matters more than it looks: the
    tenant setting that makes the insert legal is transaction-local
    (`set_config(..., true)`), so a plain rollback to recover from the collision
    would take `app.current_org` with it and every retry would fail for a second,
    unrelated reason.
    """
    candidates = [
        base_slug,
        *[f"{base_slug}-{suffix}" for suffix in range(2, 6)],
        # A random tail after the readable ones. Five numbered attempts are enough
        # for a real collision and nowhere near enough for somebody scripting the
        # same name repeatedly — which is a bad way to discover that the fallback
        # is a 409.
        f"{base_slug}-{uuid.uuid4().hex[:6]}",
    ]
    for candidate in candidates:
        org = Organization(id=org_id, name=name, slug=candidate)
        try:
            async with session.begin_nested():
                session.add(org)
                await session.flush()
        except IntegrityError as exc:
            if "ix_organizations_slug" not in str(exc.orig):
                raise
            log.info("organisation slug taken; trying the next one", extra={"slug": candidate})
            continue
        return org

    # Five collisions on one name is not bad luck, it is somebody deciding to be
    # a problem. Give them a sentence instead of a 500.
    raise AuthError("slug_taken", "that organisation name is already in use")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


async def login(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    org_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuthResult:
    """
    Verify credentials and mint a session.

    Failure is always the same error with the same timing. The five ways login
    can fail — unknown address, wrong password, deactivated account, deleted
    account, locked account — are not distinguishable from outside, and the
    attempt is recorded either way.
    """
    normalised = User.normalise_email(email)
    await set_credential(session, LOGIN_EMAIL_SETTING, normalised)

    user = (
        await session.execute(select(User).where(func.lower(User.email) == normalised))
    ).scalar_one_or_none()

    if user is None:
        # Burn the same CPU an argon2 verify would, then fail. The comparison
        # runs against a real hash of a value nobody knows, and loses.
        consume_dummy_verify(password)
        await _record_attempt(
            session,
            email=normalised,
            user=None,
            ok=False,
            reason="unknown_user",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await commit_evidence(session)
        raise AuthError("invalid_credentials", "email or password is incorrect")

    if user.is_locked:
        # `is_locked` implies `locked_until` is set. The `or` is for the type
        # checker rather than the runtime: a zero here would mean "retry now",
        # which is the right answer for a lock that has just expired.
        locked_until = user.locked_until or datetime.now(UTC)
        retry_after = int((locked_until - datetime.now(UTC)).total_seconds())
        await _record_attempt(
            session,
            email=normalised,
            user=user,
            ok=False,
            reason="locked",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await commit_evidence(session)
        raise AuthError(
            "locked",
            "too many failed attempts; try again shortly or reset your password",
            retry_after=max(1, retry_after),
        )

    # The tenant is *not* set yet, but the actor is: `users_self_update` keys off
    # app.current_user, and the failed-attempt counter below is an update to this
    # row. Without this, RLS quietly matches zero rows, `failed_login_count`
    # never increments, and the lockout threshold is decoration.
    await set_credential(session, "app.current_user", str(user.id))

    if user.password_hash is None:
        # An SSO-only account. Doing the work anyway keeps the timing flat, and
        # the message stays the same as a wrong password: "this address uses a
        # different sign-in method" would confirm the account exists.
        consume_dummy_verify(password)
        await _record_attempt(
            session,
            email=normalised,
            user=user,
            ok=False,
            reason="no_password_set",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await commit_evidence(session)
        raise AuthError("invalid_credentials", "email or password is incorrect")

    check = verify_password(password, user.password_hash)
    if not check.ok:
        locked_now = user.record_failure()
        await _record_attempt(
            session,
            email=normalised,
            user=user,
            ok=False,
            reason="bad_password",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await write_audit(
            session,
            event="user.login_failed",
            actor=user,
            target=user,
            after={"reason": "bad_password", "locked": locked_now},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await commit_evidence(session)
        raise AuthError("invalid_credentials", "email or password is incorrect")

    if not user.is_active or user.is_deleted:
        raise AuthError("inactive", "this account is not active")

    if check.needs_rehash:
        # Argon2 parameters changed since this hash was made (or will, next
        # year, when someone raises the cost). Upgrading on login is the only
        # moment the plaintext is available to rehash.
        user.password_hash = hash_password(password)

    user.record_login()
    await _record_attempt(
        session,
        email=normalised,
        user=user,
        ok=True,
        reason=None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return await issue_session(
        session,
        user=user,
        org_id=org_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )


async def issue_session(
    session: AsyncSession,
    *,
    user: User,
    org_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    rotate_from: RefreshToken | None = None,
) -> AuthResult:
    """
    Mint an access token and the next refresh token in the chain.

    `org_id` is resolved to one the user actually belongs to, or refused. It is
    never taken on trust: a client asking for a token scoped to someone else's
    org is either confused or attacking, and both deserve the same answer.
    """
    settings = get_settings()

    memberships = (
        (
            await session.execute(
                select(Membership)
                .where(Membership.user_id == user.id, Membership.suspended_at.is_(None))
                .order_by(Membership.joined_at)
            )
        )
        .scalars()
        .all()
    )

    if org_id is not None:
        membership = next((m for m in memberships if m.org_id == org_id), None)
        if membership is None:
            raise AuthError("not_a_member", "you are not a member of that organisation")
    else:
        membership = memberships[0] if memberships else None

    resolved_org = membership.org_id if membership else None
    role = membership.role if membership else None

    # Bind the session to the org now that we know it. Two things depend on it:
    # the `user.logged_in` event below names the org, so it appears in the
    # customer's audit view rather than only in ours, and the audit policy
    # requires the tenant for any row with a non-null org_id.
    if resolved_org is not None:
        from workbench.core.db import set_tenant

        await set_tenant(session, resolved_org, actor_id=user.id)

    access = mint_access_token(
        user_id=user.id,
        org_id=resolved_org,
        is_staff=user.is_staff,
    )

    plaintext = _new_refresh_value()
    token = RefreshToken(
        id=uuid7(),
        user_id=user.id,
        org_id=resolved_org,
        token_hash=hash_token(plaintext),
        family_id=rotate_from.family_id if rotate_from else uuid7(),
        parent_id=rotate_from.id if rotate_from else None,
        expires_at=RefreshToken.default_expiry(settings.refresh_token_days),
        user_agent=user_agent,
        ip_address=ip_address,
    )
    session.add(token)

    await write_audit(
        session,
        event="user.logged_in",
        actor=user,
        org_id=resolved_org,
        target=user,
        after={"org_id": str(resolved_org) if resolved_org else None, "role": role},
        ip_address=ip_address,
        user_agent=user_agent,
    )
    await session.flush()

    return AuthResult(
        user=user,
        access=access,
        refresh_token=plaintext,
        org_id=resolved_org,
        role=role,
    )


# ---------------------------------------------------------------------------
# Refresh — rotation, and what happens when a token comes back
# ---------------------------------------------------------------------------


async def refresh(
    session: AsyncSession,
    *,
    token: str,
    org_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuthResult:
    """
    Exchange a refresh token for a new pair.

    The rule this implements: **a refresh token is single-use, and its reuse is
    evidence.** A stolen token is used twice — once by the thief, once by the
    legitimate client with the older copy — and the second use is the one that
    tells you. Rotating on every use (rather than on a timer) is what turns
    "their session stopped working" into "someone had the token, here is when".

    On reuse the whole family is revoked, so the thief's freshly-minted token
    dies with the client's. Both parties are logged out and have to re-authenticate,
    which is annoying for one of them and correct for the other.
    """
    token_hash = hash_token(token)
    await set_credential(session, CREDENTIAL_SETTING, token_hash)

    record = (
        await session.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    ).scalar_one_or_none()

    if record is None:
        # Not in the database at all. Either forged, or from a rotation whose
        # rows have been pruned. Nothing to revoke, nothing to say.
        raise AuthError("invalid_refresh", "the refresh token is not valid")

    # Bind the actor the moment the owner is known, before anything is revoked.
    # `refresh_tokens` is protected by a user-scoped policy, so an UPDATE issued
    # without `app.current_user` matches zero rows — and the revocation of a
    # stolen family, which is the entire point of reuse detection, would report
    # success while doing nothing at all.
    await set_credential(session, ACTOR_SETTING, str(record.user_id))

    if record.looks_like_reuse():
        already_revoked = record.revoked_at is not None
        revoked = await revoke_family(session, record.family_id, reason="reuse_detected")
        log.warning(
            "refresh token reuse detected",
            extra={
                "user_id": str(record.user_id),
                "family_id": str(record.family_id),
                "tokens_revoked": revoked,
            },
        )
        if revoked == 0 and not already_revoked:
            # Unreachable while the policy and this call agree. Loud, because the
            # failure it represents — a reuse that revokes nothing — is invisible
            # from the outside: the response is identical either way.
            #
            # A token that was *already* revoked is the benign case: whoever
            # presents it a second time finds a family with nothing live left in
            # it, which is exactly what the first detection achieved.
            log.error(
                "reuse detection revoked nothing; check the refresh_tokens policies",
                extra={"family_id": str(record.family_id)},
            )
        await commit_evidence(session)
        raise AuthError(
            "reuse_detected",
            "this refresh token had already been used, so every session in the chain "
            "has been signed out. Sign in again.",
        )

    if record.expires_at <= datetime.now(UTC):
        record.revoke("expired")
        await commit_evidence(session)
        raise AuthError("expired_refresh", "the refresh token has expired; sign in again")

    user = (
        await session.execute(select(User).where(User.id == record.user_id))
    ).scalar_one_or_none()
    if user is None or not user.is_active or user.is_deleted:
        await revoke_family(session, record.family_id, reason="user_inactive")
        await commit_evidence(session)
        raise AuthError("inactive", "this account is not active")

    record.rotate()
    result = await issue_session(
        session,
        user=user,
        org_id=org_id if org_id is not None else record.org_id,
        ip_address=ip_address,
        user_agent=user_agent,
        rotate_from=record,
    )
    await session.flush()
    return result


async def revoke_family(session: AsyncSession, family_id: uuid.UUID, *, reason: str) -> int:
    """Revoke every token in a rotation chain. Returns how many were live."""
    now = datetime.now(UTC)
    tokens = (
        (
            await session.execute(
                select(RefreshToken).where(
                    RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    for token in tokens:
        token.revoked_at = now
        token.revoked_reason = reason
    return len(tokens)


async def revoke_family_for_user(session: AsyncSession, *, user_id: uuid.UUID, reason: str) -> int:
    """
    Revoke every live refresh chain this user holds.

    Called after a password change or a completed reset. Not called on logout —
    that revokes one chain, because signing out on a laptop should not sign you
    out on your phone.
    """
    now = datetime.now(UTC)
    live = (
        (
            await session.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    for record in live:
        record.revoked_at = now
        record.revoked_reason = reason
    return len(live)


async def logout(
    session: AsyncSession,
    *,
    token: str | None,
    user: User,
    all_devices: bool = False,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> int:
    """
    Revoke this device's chain, or every chain the user has.

    Access tokens remain valid until they expire — up to fifteen minutes. Making
    logout instant would need a session table read on every request, which is the
    trade the token design already made. `all_devices` at least kills the refresh
    chains, so the fifteen minutes is the ceiling rather than the beginning.
    """
    await set_credential(session, "app.current_user", str(user.id))
    revoked = 0

    if all_devices:
        live = (
            (
                await session.execute(
                    select(RefreshToken).where(
                        RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        for record in live:
            record.revoked_at = now
            record.revoked_reason = "logout_all"
        revoked = len(live)
    elif token:
        token_hash = hash_token(token)
        presented = (
            await session.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        ).scalar_one_or_none()
        if presented is not None and presented.user_id == user.id and presented.revoked_at is None:
            presented.revoke("logout")
            revoked = 1

    await write_audit(
        session,
        event="user.logged_out",
        actor=user,
        target=user,
        after={"all_devices": all_devices, "revoked": revoked},
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return revoked


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


async def create_api_key(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    created_by: User,
    name: str,
    scopes: list[str],
    expires_in_days: int | None = None,
) -> tuple[ApiKey, str]:
    """
    Mint a key, and narrow its scopes to what its creator may do.

    Intersecting scopes with the creator's role is the whole security model of
    API keys in one line. Without it, a viewer mints a key with `billing:write`,
    because the request said so and nothing checked.
    """
    from workbench.auth.passwords import generate_api_key
    from workbench.core.permissions import permissions_for

    membership = (
        await session.execute(
            select(Membership).where(
                Membership.user_id == created_by.id, Membership.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        raise AuthError("not_a_member", "you are not a member of that organisation")

    allowed = permissions_for(membership.role)
    effective = sorted(set(scopes) & set(allowed)) if scopes else sorted(allowed)
    if not effective:
        raise AuthError(
            "empty_scopes",
            "none of the requested scopes are available to your role in this organisation",
        )

    material = generate_api_key(environment=get_settings().environment)
    key = ApiKey(
        id=uuid7(),
        org_id=org_id,
        created_by_id=created_by.id,
        name=name,
        prefix=material.prefix,
        secret_hash=material.secret_hash,
        scopes=effective,
        expires_at=(
            datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None
        ),
    )
    session.add(key)
    await session.flush()

    await write_audit(
        session,
        event="apikey.created",
        actor=created_by,
        org_id=org_id,
        target=key,
        after={"name": name, "prefix": material.prefix, "scopes": effective},
    )
    # The plaintext is returned once and never stored. If the client loses it,
    # the answer is a new key, not a recovery flow.
    return key, material.plaintext


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _record_attempt(
    session: AsyncSession,
    *,
    email: str,
    user: User | None,
    ok: bool,
    reason: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> None:
    session.add(
        LoginAttempt(
            id=uuid7(),
            email=email,
            user_id=user.id if user else None,
            succeeded=ok,
            failure_reason=reason,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:400] or None,
        )
    )


def _new_refresh_value() -> str:
    import secrets

    return secrets.token_urlsafe(48)


def _mask(value: str) -> str:
    """Never log an address in full. Two thirds of it is a customer's identity."""
    local, _, domain = value.partition("@")
    return f"{local[:2]}***@{domain}"


def mask_email(value: str) -> str:
    """Public alias — the console uses it too."""
    return _mask(value)


def summarise_attempts(rows: list[LoginAttempt]) -> dict[str, Any]:
    """Small helper the staff console uses; kept here so the shape is in one place."""
    return {
        "total": len(rows),
        "failed": sum(1 for row in rows if not row.succeeded),
        "reasons": sorted({row.failure_reason for row in rows if row.failure_reason}),
    }
