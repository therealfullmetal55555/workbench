"""
Writing audit events.

`write_audit()` takes the session and writes on it, so the event lands in the
same transaction as the change it describes. If the change rolls back, so does
the record of it. That's the difference between an audit log and a log of things
that looked like they were going to happen.

    async with tenant_session(...) as session:
        before = org.plan_code
        org.plan_code = "enterprise"
        await write_audit(session, event="billing.plan_changed",
                          actor=current_user, target=org,
                          before={"plan_code": before},
                          after={"plan_code": "enterprise"})

Never `await session.commit()` inside this module. The caller owns the
transaction boundary; committing here would split the change and its record.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from workbench.audit.models import ACTOR_KINDS, EVENT_KINDS, AuditEvent, redact

log = logging.getLogger(__name__)


class AuditError(RuntimeError):
    """Raised when an event can't be written. Fails the surrounding transaction."""


async def write_audit(
    session: AsyncSession,
    *,
    event: str,
    actor: Any = None,
    actor_kind: str | None = None,
    org_id: uuid.UUID | str | None = None,
    target: Any = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    target_label: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reason: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    impersonated: bool = False,
    impersonation_id: uuid.UUID | None = None,
) -> AuditEvent:
    """
    Append one event to the log.

    Everything is keyword-only and most of it is optional because the two things
    that must never be forgotten are `event` and the org — and callers who have
    to fill in twelve positional arguments will pass the wrong ones.
    """
    if event not in EVENT_KINDS:
        # A typo'd event name is a filter that never matches, which is a
        # dashboard that silently shows nothing. Loud at the first occurrence
        # beats quiet forever.
        raise AuditError(
            f"unknown audit event '{event}'. Add it to EVENT_KINDS in audit/models.py — "
            "an event name that isn't in the list is a filter that will never match."
        )

    acting = resolve_actor(
        actor,
        actor_kind=actor_kind,
        impersonated=impersonated,
        impersonation_id=impersonation_id,
    )
    if acting.kind not in ACTOR_KINDS:
        raise AuditError(f"unknown actor_kind '{acting.kind}'")

    if actor_kind == "staff" and not reason:
        # "Why did someone look at this customer's account" is the only question
        # that matters after an access review, and it can't be reconstructed
        # later.
        #
        # Keyed on the *explicit* `actor_kind="staff"`, not on the inferred kind,
        # and that distinction is the difference between a useful rule and a bug.
        # Inferring it from `user.is_staff` meant that a support engineer signing
        # into their own account — a `user.logged_in` event, nothing to do with
        # any customer — raised here and 500'd the login. Acting as staff is a
        # claim the console makes deliberately; it says who is acting on whose
        # behalf, and that is the thing that must come with a reason.
        raise AuditError("staff actions must carry a reason")

    if org_id is None and target is not None:
        org_id = _org_id_of(target)
    if org_id is None and actor is not None:
        org_id = _org_id_of(actor)

    if target is not None:
        target_type = target_type or type(target).__name__.lower()
        target_id = target_id or getattr(target, "id", None)
        target_label = target_label or _label_for(target)

    audit_event = AuditEvent(
        event=event,
        org_id=_as_uuid(org_id),
        actor_kind=acting.kind,
        actor_id=acting.id,
        actor_email=acting.email,
        impersonated=acting.impersonated,
        impersonation_id=acting.impersonation_id,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_label=target_label,
        # Redaction happens here rather than at the call site, so a caller who
        # forgets still can't write a password hash into an immutable table.
        before=redact(_as_dict(before)),
        after=redact(_as_dict(after)),
        reason=reason,
        ip_address=ip_address,
        user_agent=_truncate(user_agent, 400),
        request_id=request_id,
    )

    session.add(audit_event)

    # Flush, don't commit. Flushing surfaces a constraint violation now, while
    # the caller can still do something about it; committing would take the
    # transaction boundary away from them.
    await session.flush()

    log.info(
        "audit",
        extra={
            "event": event,
            "org_id": str(org_id) if org_id else None,
            "actor_id": str(acting.id) if acting.id else None,
            "actor_kind": acting.kind,
            "target_id": audit_event.target_id,
            "impersonated": impersonated,
        },
    )
    return audit_event


@contextlib.asynccontextmanager
async def audit_scope(
    session: AsyncSession,
    *,
    event: str,
    actor: Any = None,
    **kwargs: Any,
) -> AsyncIterator[_Scope]:
    """
    Write one event describing a block, with the outcome.

        async with audit_scope(session, event="billing.plan_changed",
                               actor=user, org_id=org.id) as scope:
            scope.before = {"plan": org.plan_code}
            org.plan_code = "enterprise"
            scope.after = {"plan": org.plan_code}

    On an exception, the event is still written with `failed: true` in `after`
    and the transaction is left for the caller to roll back — so a failed attempt
    is recorded if the surrounding transaction survives, and rolled back with it
    if it doesn't. Either way the log never claims something happened that didn't.
    """
    scope = _Scope()
    try:
        yield scope
    except Exception as exc:
        with contextlib.suppress(Exception):
            await write_audit(
                session,
                event=event,
                actor=actor,
                before=scope.before,
                after={**(scope.after or {}), "failed": True, "error": type(exc).__name__},
                **kwargs,
            )
        raise
    else:
        await write_audit(
            session,
            event=event,
            actor=actor,
            before=scope.before,
            after=scope.after,
            **kwargs,
        )


class _Scope:
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class _Actor:
    kind: str
    id: uuid.UUID | None
    email: str | None
    impersonated: bool = False
    impersonation_id: uuid.UUID | None = None


def resolve_actor(
    actor: Any,
    *,
    actor_kind: str | None = None,
    impersonated: bool = False,
    impersonation_id: uuid.UUID | None = None,
) -> _Actor:
    """
    Unpack whatever the caller thinks an actor is into the columns that exist.

    Three shapes arrive here, and they did not agree with each other. Routes pass
    `scope.actor`, which is a `Principal`; the signup and login paths pass a
    `User`; the webhook path passes nothing. The old inference looked for an
    `email` attribute, found none on a `Principal`, and quietly recorded
    `actor_kind="system"` with a null id — so `member.invited`, `apikey.created`
    and everything else written from a route was logged as having been done by
    nobody. The audit view still looked plausible, which is why it survived: an
    event with no actor is easy to read as a background job.

    A `Principal` also knows things the call site would otherwise have to repeat:
    whether the request is an impersonation, and which impersonation row is
    responsible. Those are recovered here rather than passed in twelve places.
    """
    if actor is None:
        return _Actor(actor_kind or "system", None, None, impersonated, impersonation_id)

    # A Principal wraps either a person or an API key. Unwrap before inspecting,
    # or the check below sees neither and falls through to "system".
    key = getattr(actor, "api_key", None)
    user = getattr(actor, "user", None)
    if key is not None or user is not None:
        acting = key if key is not None else user
        record = getattr(actor, "impersonation", None)
        if record is not None:
            impersonated = True
            impersonation_id = impersonation_id or getattr(record, "id", None)
        return resolve_actor(
            acting,
            actor_kind=actor_kind,
            impersonated=impersonated,
            impersonation_id=impersonation_id,
        )

    if hasattr(actor, "prefix"):  # ApiKey
        # The key has no identity of its own, so the actor is whoever minted it:
        # the same person the request was authorised as.
        return _Actor(
            actor_kind or "api_key",
            _as_uuid(getattr(actor, "created_by_id", None)),
            None,
            impersonated,
            impersonation_id,
        )

    if hasattr(actor, "email") or hasattr(actor, "password_hash"):  # User
        kind = actor_kind or ("staff" if getattr(actor, "is_staff", False) else "user")
        return _Actor(
            kind,
            _as_uuid(getattr(actor, "id", None)),
            getattr(actor, "email", None),
            impersonated,
            impersonation_id,
        )

    return _Actor(actor_kind or "system", None, None, impersonated, impersonation_id)


def _infer_actor_kind(actor: Any) -> str:
    """Kept for callers that only need the kind. See `resolve_actor`."""
    return resolve_actor(actor).kind


def _org_id_of(value: Any) -> uuid.UUID | str | None:
    """
    The organisation a row belongs to — which is not always its `org_id`.

    Every tenant-scoped table has `org_id`, so one `getattr` covers almost
    everything. The organisation itself is the exception: it has no `org_id`,
    because it *is* the org. `org.created` was therefore written with a null org
    and, since the audit policy scopes reads by `org_id`, could not be read from
    the very org it describes. The one event that proves the account was created
    was invisible in the account's own log.
    """
    org = getattr(value, "org_id", None)
    if org is not None:
        return org
    if getattr(value, "__tablename__", None) == "organizations":
        return getattr(value, "id", None)
    return None


def _label_for(target: Any) -> str | None:
    """Prefer a name a human would recognise, captured now rather than joined later."""
    for attribute in ("name", "title", "label", "slug", "prefix"):
        value = getattr(target, attribute, None)
        if isinstance(value, str) and value:
            return _truncate(value, 200)
    return None


def _as_dict(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return {"value": value}
    return value


def _as_uuid(value: Any) -> uuid.UUID | None:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value[:limit]
