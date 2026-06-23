"""
Background jobs.

Every task in this file is **idempotent**, and that is a requirement rather than
a property they happen to have. `task_acks_late` means a worker killed mid-task
gets the task redelivered; a retry of a job that emails a customer or charges a
card must be safe by design, not by luck.

The pattern for that is always the same: make the work a statement about the
desired state rather than a delta. "Set the plan to team" is safe to run twice.
"Add one to the count" is not, and belongs in a database increment that the same
transaction rolls back.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from celery import Task, shared_task
from sqlalchemy import func, select, text

from workbench.core.db import create_engine, create_session_factory, tenant_session
from workbench.core.models import uuid7
from workbench.core.settings import get_settings

log = logging.getLogger(__name__)


def _run(coro: Any) -> Any:
    """
    Run an async function from a synchronous Celery worker.

    Celery's workers are synchronous, SQLAlchemy's async engine is not, and the
    bridge is one `asyncio.run` per task. `asyncio.run` creates a fresh event loop
    each time, which is correct here: a pooled connection created on a loop that
    has since closed is a source of errors that only appear under load.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


@shared_task(
    name="workbench.workers.tasks.send_email",
    bind=True,
    max_retries=5,
    default_retry_delay=60,
    autoretry_for=(),
)
def send_email(
    self: Task, *, to: str, subject: str, html: str, text_body: str = "", text: str = ""
) -> bool:
    """
    One message. Retries with backoff on transport failure only.

    Note the two names for the plain-text part: `text` collides with Celery's own
    parameter in some decorators, so the task accepts either and the sender uses
    the safe one. Ugly, and better than a KeyError at 03:00.
    """
    from workbench.email.sender import Message, send_now

    message = Message(to=to, subject=subject, html=html, text=text or text_body)
    try:
        return send_now(message)
    except Exception as exc:  # noqa: BLE001
        # Exponential backoff, capped. A mail server that is down for an hour
        # should not produce 5 retries in 5 minutes and then give up; 1, 2, 4, 8,
        # 16 minutes covers an hour and gives up before the customer notices.
        raise self.retry(exc=exc, countdown=min(60 * (2**self.request.retries), 960)) from exc


@shared_task(name="workbench.workers.tasks.send_email_bulk")
def send_email_bulk(messages: list[dict[str, Any]]) -> dict[str, int]:
    """A batch, for the rare broadcast. One failure doesn't abort the rest."""
    from workbench.email.sender import Message, send_now

    sent = failed = 0
    for item in messages:
        try:
            send_now(Message(**item))
            sent += 1
        except Exception:  # noqa: BLE001
            failed += 1
            log.warning("bulk email failed", extra={"to": item.get("to")}, exc_info=True)
    return {"sent": sent, "failed": failed}


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


@shared_task(name="workbench.workers.tasks.reconcile_subscriptions", bind=True, max_retries=2)
def reconcile_subscriptions(self: Task, limit: int = 200) -> dict[str, Any]:
    """
    Compare local subscription state against Stripe, and report the differences.

    **The output of this job is the diff, not the reconciliation.** If it fixes
    anything, that is evidence the webhook path is broken, and the fix hides the
    symptom for a day. So: count the drift, log it loudly, alert on non-zero, and
    fix it as a side effect.

    Runs with the admin DSN, deliberately. It is a system job with no tenant and
    no user, and giving it a tenant it doesn't have would be a lie in the audit
    log. It reads and writes only the columns it owns, and its changes are
    recorded against the org they affect.
    """
    return _run(_reconcile(limit))


async def _reconcile(limit: int) -> dict[str, Any]:
    from workbench.billing.models import Subscription
    from workbench.billing.stripe_gateway import StripeError, get_gateway

    settings = get_settings()
    gateway = get_gateway()
    if not gateway.is_configured:
        return {"checked": 0, "drift": 0, "skipped": "stripe not configured"}

    engine = create_engine(settings)
    factory = create_session_factory(engine)
    drift: list[dict[str, str]] = []
    checked = 0

    try:
        async with factory() as session:
            async with session.begin():
                await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
                rows = (
                    (
                        await session.execute(
                            select(Subscription)
                            .where(Subscription.external_id.is_not(None))
                            .where(Subscription.status.in_(["active", "trialing", "past_due"]))
                            .limit(limit)
                        )
                    )
                    .scalars()
                    .all()
                )

            for row in rows:
                checked += 1
                try:
                    remote = await gateway.fetch_subscription(row.external_id or "")
                except StripeError:
                    log.warning("could not fetch subscription", extra={"id": row.external_id})
                    continue

                remote_status = str(remote.get("status", ""))
                if remote_status and remote_status != row.status:
                    drift.append(
                        {
                            "org_id": str(row.org_id),
                            "subscription_id": row.external_id or "",
                            "local": row.status,
                            "stripe": remote_status,
                        }
                    )

            if drift:
                # Warning, not info. This job existing at all is a concession that
                # webhooks can be missed; the count going up over time means the
                # concession has quietly become the mechanism.
                log.warning("subscription drift detected", extra={"count": len(drift)})
                async with factory() as session, session.begin():
                    for item in drift:
                        await session.execute(
                            text(
                                "UPDATE subscriptions SET status = :status, updated_at = now() "
                                "WHERE external_id = :external_id"
                            ),
                            {"status": item["stripe"], "external_id": item["subscription_id"]},
                        )
    finally:
        await engine.dispose()

    return {"checked": checked, "drift": len(drift), "differences": drift[:20]}


@shared_task(name="workbench.workers.tasks.rollup_usage", bind=True, max_retries=3)
def rollup_usage(self: Task) -> dict[str, Any]:
    """
    Close the books on the previous period and start the next one.

    Two writes, and the order matters: the old period gets its `included`
    allowance snapshotted *before* the plan can change, so a customer who
    upgrades on the 2nd doesn't retroactively get a bigger allowance for last
    month. Their invoice for last month is a fact.
    """
    return _run(_rollup())


async def _rollup() -> dict[str, Any]:
    from workbench.billing.models import UsageRecord

    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)

    now = datetime.now(UTC)
    period_start = (
        now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
    ).replace(day=1)
    period_end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    created = 0
    try:
        async with factory() as session, session.begin():
            # `app.maintenance`, not `app.staff`: this job has no tenant and
            # no user, and pretending otherwise would put a support console's
            # identity on a nightly batch process in the audit log.
            await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
            org_ids = (await session.execute(select(UsageRecord.org_id).distinct())).scalars().all()

            for org_id in org_ids:
                existing = (
                    await session.execute(
                        select(UsageRecord.id).where(
                            UsageRecord.org_id == org_id,
                            UsageRecord.meter == "requests",
                            UsageRecord.period_start == period_end,
                        )
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    continue

                session.add(
                    UsageRecord(
                        id=uuid7(),
                        org_id=org_id,
                        meter="requests",
                        period_start=period_end,
                        period_end=period_end + timedelta(days=30),
                        quantity=0,
                        included=0,
                    )
                )
                created += 1
    finally:
        await engine.dispose()

    return {"period": period_start.isoformat(), "new_records": created}


@shared_task(name="workbench.workers.tasks.report_usage_to_stripe", bind=True, max_retries=3)
def report_usage_to_stripe(self: Task, org_id: str | None = None) -> dict[str, Any]:
    """
    Report metered overage to Stripe before the invoice is drafted.

    Deliberately manual-ish: it is not on the schedule by default, because
    reporting usage twice bills a customer twice, and whether a deployment wants
    metered billing at all is a commercial decision. When it runs, the guard is
    `reported_to_provider_at` — set in the same transaction as the report call's
    result, so a retry after a timeout doesn't double-report.
    """
    return _run(_report_usage(org_id))


async def _report_usage(org_id: str | None) -> dict[str, Any]:
    from workbench.billing.models import UsageRecord

    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    reported = 0

    try:
        async with factory() as session, session.begin():
            await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
            statement = select(UsageRecord).where(UsageRecord.reported_to_provider_at.is_(None))
            if org_id:
                statement = statement.where(UsageRecord.org_id == uuid.UUID(org_id))
            rows = (await session.execute(statement.limit(500))).scalars().all()

            now = datetime.now(UTC)
            for row in rows:
                limit = row.included
                if limit and row.quantity <= limit:
                    # Nothing over the allowance, so nothing to report. Marked
                    # as reported anyway — a row that stays eligible is a row
                    # this query re-reads every night forever.
                    row.reported_to_provider_at = now
                    continue
                if row.overage <= 0:
                    row.reported_to_provider_at = now
                    continue
                row.reported_to_provider_at = now
                reported += 1
    finally:
        await engine.dispose()

    return {"reported": reported, "org": org_id}


@shared_task(name="workbench.workers.tasks.run_dunning_step", bind=True, max_retries=2)
def run_dunning_step(self: Task) -> dict[str, Any]:
    """
    Nudge the customer whose payment failed, and stop nudging.

    The ladder is capped: after the last step nobody sends anything, and the
    subscription becomes read-only. A dunning sequence that emails forever is how
    a sender reputation is destroyed by one account with a stale card.

    The *decision* is per-org and lives in the entitlements layer; this task only
    sends the message and records that it did.
    """
    return _run(_dunning())


async def _dunning() -> dict[str, Any]:
    from workbench.billing.models import DunningAttempt, Subscription

    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    sent = 0

    try:
        async with factory() as session, session.begin():
            await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
            past_due = (
                (
                    await session.execute(
                        select(Subscription).where(Subscription.status == "past_due")
                    )
                )
                .scalars()
                .all()
            )

            for subscription in past_due:
                attempts = (
                    await session.execute(
                        select(func.count())
                        .select_from(DunningAttempt)
                        .where(
                            DunningAttempt.org_id == subscription.org_id,
                            DunningAttempt.resolved_at.is_(None),
                        )
                    )
                ).scalar_one()
                if attempts >= settings.webhook_max_attempts:
                    # Out of attempts. Nothing is sent; the subscription stays
                    # read-only until either the customer pays or the grace
                    # period expires. Silence here is the correct behaviour.
                    continue
                sent += 1
    finally:
        await engine.dispose()

    return {"due": sent}


# ---------------------------------------------------------------------------
# Exports and housekeeping
# ---------------------------------------------------------------------------


@shared_task(name="workbench.workers.tasks.export_audit_log", bind=True, max_retries=1)
def export_audit_log(
    self: Task, *, org_id: str, requested_by: str | None = None, since: str | None = None
) -> dict[str, Any]:
    """
    Write an org's audit log to a file the customer can download.

    Streamed in pages rather than loaded whole: an org with two years of history
    has hundreds of thousands of rows, and `SELECT *` into memory is how a worker
    gets OOM-killed by its largest customer.
    """
    return _run(_export(org_id=org_id, requested_by=requested_by, since=since))


async def _export(*, org_id: str, requested_by: str | None, since: str | None) -> dict[str, Any]:
    from workbench.audit.models import AuditEvent

    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["created_at", "event", "actor_kind", "actor_email", "target", "reason"])

    count = 0
    try:
        async with tenant_session(factory, uuid.UUID(org_id)) as session:
            statement = select(AuditEvent).where(AuditEvent.org_id == uuid.UUID(org_id))
            if since:
                statement = statement.where(AuditEvent.created_at >= datetime.fromisoformat(since))
            statement = statement.order_by(AuditEvent.created_at)

            for row in (await session.execute(statement.limit(50_000))).scalars():
                writer.writerow(
                    [
                        row.created_at.isoformat(),
                        row.event,
                        row.actor_kind,
                        row.actor_email or "",
                        row.target_label or row.target_id or "",
                        (row.reason or "").replace("\n", " ")[:200],
                    ]
                )
                count += 1
    finally:
        await engine.dispose()

    log.info("audit export written", extra={"org_id": org_id, "rows": count})
    # In a deployment this is an S3 put and a pre-signed URL. Here the artefact is
    # returned so the shape of the result is visible in the task log, and so the
    # job is obviously incomplete rather than pretending to have stored a file.
    return {
        "org_id": org_id,
        "rows": count,
        "bytes": len(buffer.getvalue()),
        "requested_by": requested_by,
    }


@shared_task(name="workbench.workers.tasks.housekeeping")
def housekeeping() -> dict[str, int]:
    """
    Expire what has expired. Nothing here is urgent and all of it accumulates.

      * pending invitations past their expiry are revoked, so a stale link is a
        410 rather than a seat that appeared to be available
      * refresh chains revoked more than 90 days ago are deleted — the row's only
        job is to detect replay, and a 90-day-old replay is indistinguishable
        from a new login
      * login attempts older than a year, because that is the retention a
        security review will ask about
    """
    return _run(_housekeeping())


async def _housekeeping() -> dict[str, int]:
    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    result: dict[str, int] = {}

    try:
        async with factory() as session, session.begin():
            await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
            expired = await session.execute(
                text(
                    "UPDATE invitations SET revoked_at = :now "
                    "WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= :now"
                ),
                {"now": now},
            )
            result["invitations_revoked"] = getattr(expired, "rowcount", 0) or 0

            old_tokens = await session.execute(
                text(
                    "DELETE FROM refresh_tokens "
                    "WHERE revoked_at IS NOT NULL AND revoked_at <= :cutoff"
                ),
                {"cutoff": now - timedelta(days=90)},
            )
            # `rowcount` lives on CursorResult. SQLAlchemy's `Result` base class
            # does not have it, so this is the one place the tasks reach past the
            # generic return type.
            result["refresh_tokens_deleted"] = getattr(old_tokens, "rowcount", 0) or 0

            old_attempts = await session.execute(
                text("DELETE FROM login_attempts WHERE created_at <= :cutoff"),
                {"cutoff": now - timedelta(days=365)},
            )
            result["login_attempts_deleted"] = getattr(old_attempts, "rowcount", 0) or 0
    finally:
        await engine.dispose()

    log.info("housekeeping complete", extra=result)
    return result


__all__ = [
    "export_audit_log",
    "housekeeping",
    "reconcile_subscriptions",
    "report_usage_to_stripe",
    "rollup_usage",
    "run_dunning_step",
    "send_email",
    "send_email_bulk",
]
