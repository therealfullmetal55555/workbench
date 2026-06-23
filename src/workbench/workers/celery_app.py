"""
The worker.

Four queues, separated by what a failure costs:

    email    — losing one is annoying. Retried, but never blocks anything.
    billing  — reconciling usage and reporting it to Stripe. Money, so it gets
               its own queue: a slow export must not delay the job that tells
               Stripe how much to bill.
    default  — everything else, exports included.
    beat     — nothing. The scheduler, kept separate so a stuck task in `default`
               can't delay the rollup that runs at midnight.

A separate queue for billing is not premature scale engineering; it is the
difference between "the usage report ran late" and "the usage report ran late and
so did the invoice".

Retries are declared per task rather than globally. `autoretry_for=(Exception,)`
looks tidy and is how a task that will never succeed — a malformed payload —
retries 30 times over four hours and fills the log with the same traceback.
"""

from __future__ import annotations

import logging
import os
import sys

from celery import Celery
from celery.signals import setup_logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from workbench.core.settings import get_settings  # noqa: E402

settings = get_settings()

app = Celery(
    "workbench",
    broker=str(settings.redis_dsn),
    backend=str(settings.redis_dsn),
    include=["workbench.workers.tasks"],
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # A worker that acknowledges a task before running it loses the task when the
    # process is killed mid-run. `acks_late` means a crash re-delivers it — which
    # is only safe because every task here is idempotent, and that is a
    # requirement on new tasks, not a hope.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # One task at a time per worker process. Emails and rollups are I/O-bound, so
    # prefetching 4× the concurrency is just 4× the memory for no throughput.
    worker_prefetch_multiplier=1,
    # A hard ceiling, so a task waiting on a dead socket doesn't hold a slot for
    # an hour. The socket timeouts in the code are the real defence; this is the
    # backstop.
    task_time_limit=600,
    task_soft_time_limit=540,
    task_default_queue="default",
    task_routes={
        "workbench.workers.tasks.send_email": {"queue": "email"},
        "workbench.workers.tasks.send_email_bulk": {"queue": "email"},
        "workbench.workers.tasks.reconcile_subscriptions": {"queue": "billing"},
        "workbench.workers.tasks.report_usage_to_stripe": {"queue": "billing"},
        "workbench.workers.tasks.run_dunning_step": {"queue": "billing"},
        "workbench.workers.tasks.rollup_usage": {"queue": "billing"},
    },
    beat_schedule={
        # Every hour: bring local subscription state in line with Stripe. The
        # webhook should have already done this, so the job's real output is the
        # *difference* — a non-empty result is an alert, not a success.
        "reconcile-subscriptions": {
            "task": "workbench.workers.tasks.reconcile_subscriptions",
            "schedule": 3600.0,
        },
        # Nightly: fold last month's usage into a settled number, and report the
        # metered overage to Stripe before the invoice is drafted.
        "rollup-usage": {
            "task": "workbench.workers.tasks.rollup_usage",
            "schedule": 60.0 * 60.0 * 24,
        },
        # Dunning checks whether a past_due subscription has recovered. It does
        # not send anything on its own — see the task for why.
        "dunning": {
            "task": "workbench.workers.tasks.run_dunning_step",
            "schedule": 60.0 * 60.0 * 6,
        },
        # Clean up expired invitations and dead refresh chains. Small, constant
        # work that nobody notices until the tables are huge.
        "housekeeping": {
            "task": "workbench.workers.tasks.housekeeping",
            "schedule": 60.0 * 60.0 * 24,
        },
    },
)


@setup_logging.connect
def _configure_logging(**_kwargs: object) -> None:
    """
    Take over Celery's logging.

    Celery installs its own handlers at import. Without this the worker's logs
    are formatted differently from the API's, so a request id that appears in one
    cannot be grepped in the other — which is the entire point of having them.
    """
    from workbench.main import configure_logging

    configure_logging(settings)


def heartbeat() -> dict[str, str]:
    """Cheap liveness check: `celery -A workbench.workers.celery_app inspect ping`."""
    return {"service": "workbench-worker", "version": settings.service_version}


log = logging.getLogger(__name__)
log.debug("celery configured", extra={"broker": str(settings.redis_dsn).split("@")[-1]})

__all__ = ["app", "heartbeat"]
