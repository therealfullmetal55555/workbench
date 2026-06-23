"""
Transactional email.

Two functions and a rule: **a request never waits for SMTP.**

Sending inline means the signup request's latency is the mail server's latency,
and when the mail server is slow every signup starts timing out at the load
balancer — a mail problem promoted to a product outage. So routers call
`enqueue()`, which hands the message to a worker and returns. Only the worker
calls `send_now()`.

Templates come in pairs — `.html` and `.txt`. The plain-text part is not a
courtesy: a message with no text alternative scores worse with every major
provider, and a link inside an HTML-only email is unclickable in the plain-text
clients that security-conscious customers use. A test asserts every HTML
template has a text twin, because the failure mode is silent — it looks fine in
your inbox and is unreadable in theirs.

The templates inline their CSS on purpose. `<style>` blocks are stripped by
Gmail and Outlook for exactly the messages you care about.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from workbench.core.settings import get_settings

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

# The subjects live here, not in the templates: a subject is what a customer sees
# in a list of forty, and keeping them in one place makes it possible to read
# them all at once and notice that four of them start the same way.
SUBJECTS: dict[str, str] = {
    "verification": "Confirm your email address",
    "invitation": "You have been invited to {org_name}",
    "password_reset": "Reset your workbench password",
    "payment_failed": "We could not take your payment",
    "quota_warning": "You have used {percent}% of your monthly requests",
}


@dataclass(frozen=True, slots=True)
class Message:
    to: str
    subject: str
    html: str
    text: str
    reply_to: str | None = None

    @property
    def is_empty(self) -> bool:
        return not (self.html.strip() or self.text.strip())


@lru_cache(maxsize=1)
def environment() -> Environment:
    """
    One Jinja environment, with `StrictUndefined`.

    Strict matters for email more than for HTML pages: a template that renders
    `Hello, !` because someone renamed a variable produces a message that goes
    out, gets read, and cannot be recalled. An exception in the worker produces a
    retry and a log line.
    """
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(template: str, **context: Any) -> Message:
    """
    Render both parts of one email.

    Raises `FileNotFoundError` for an unknown template rather than sending an
    empty message — an empty email is worse than a failed job, because the failed
    job is visible.
    """
    env = environment()
    context.setdefault("product", "workbench")

    html = env.get_template(f"{template}.html").render(**context)
    text = env.get_template(f"{template}.txt").render(**context)

    subject_template = SUBJECTS.get(template, "A message from workbench")
    subject = subject_template.format(**context) if "{" in subject_template else subject_template

    return Message(to=context.get("to", ""), subject=subject, html=html, text=text)


def send_now(message: Message) -> bool:
    """
    Blocking send. Only ever called from a worker.

    Returns False instead of raising when SMTP is unconfigured: in development
    there is no mail server and a signup should still succeed, so the message is
    logged. In production an unset SMTP_URL is a configuration error and the
    startup check for it lives in `Settings._validate_production`.
    """
    settings = get_settings()
    if not settings.smtp_url:
        log.info(
            "email not sent — no SMTP configured",
            extra={"to": _mask(message.to), "subject": message.subject},
        )
        return False

    payload = EmailMessage()
    payload["From"] = settings.mail_from
    payload["To"] = message.to
    payload["Subject"] = message.subject
    if message.reply_to:
        payload["Reply-To"] = message.reply_to
    # Text first, then HTML: `set_content` then `add_alternative` produces a
    # multipart/alternative whose last part is the preferred one. Reversed, every
    # client shows the plain text.
    payload.set_content(message.text)
    payload.add_alternative(message.html, subtype="html")

    host, port, username, password, mode = _parse_smtp_url(settings.smtp_url)
    # A username without a password is a misconfigured URL, not an anonymous
    # server: SMTP has no "authenticate with no secret" option, and passing None
    # to `login` raises a TypeError from inside smtplib with a traceback that
    # names nobody's configuration.
    credentials = (username, password) if username and password is not None else None

    try:
        if mode == "ssl":
            # Port 465 is implicit TLS: the connection is encrypted from the
            # first byte. Calling starttls() on it fails, and "just use
            # starttls" is the mistake that makes 465 look broken.
            with smtplib.SMTP_SSL(host, port, timeout=10) as client:
                if credentials:
                    client.login(*credentials)
                client.send_message(payload)
        else:
            with smtplib.SMTP(host, port, timeout=10) as client:
                if mode == "starttls":
                    client.starttls()
                if credentials:
                    client.login(*credentials)
                client.send_message(payload)
    except (OSError, smtplib.SMTPException):
        # Let the worker retry. Swallowing it here would mean a customer never
        # gets their invitation and nobody finds out.
        log.exception("email send failed", extra={"to": _mask(message.to)})
        raise

    log.info("email sent", extra={"to": _mask(message.to), "subject": message.subject})
    return True


def enqueue(template: str, *, to: str, **context: Any) -> None:
    """
    Render now, send later.

    Rendering happens here rather than in the task so a broken template fails
    the request that can still tell someone, instead of failing in a worker where
    the only signal is a retry counter.

    Delivery is best-effort, and that is a decision: a signup that fails because
    the mail server is down is a signup lost. The message is logged if it can't
    be queued, and the customer can request it again from the UI.
    """
    try:
        message = render(template, to=to, **context)
    except Exception:  # noqa: BLE001 — a template error must not fail the request
        log.exception("email template failed to render", extra={"template": template})
        return

    try:
        from workbench.workers.tasks import send_email

        send_email.delay(
            to=message.to, subject=message.subject, html=message.html, text=message.text
        )
    except Exception:  # noqa: BLE001 — no broker in dev, no celery installed, broker down
        log.warning(
            "email task not queued; sending inline",
            extra={"template": template, "to": _mask(to)},
        )
        try:
            send_now(message)
        except Exception:  # noqa: BLE001
            log.exception("inline email send failed", extra={"template": template})


def _parse_smtp_url(url: str) -> tuple[str, int, str | None, str | None, str]:
    """
    Returns `(host, port, username, password, mode)`.

    `mode` is one of `plain` (mailhog, a relay on a private network),
    `starttls` (587, what most providers want) or `ssl` (465). The three are not
    interchangeable and the difference is a support ticket every time.
    """
    from urllib.parse import unquote, urlparse

    parsed = urlparse(url)
    if parsed.scheme in {"smtps", "smtp+ssl"} or parsed.port == 465:
        mode = "ssl"
    elif parsed.scheme in {"smtp+tls", "smtp+starttls"} or parsed.port == 587:
        mode = "starttls"
    else:
        mode = "plain"

    default_port = {"ssl": 465, "starttls": 587, "plain": 25}[mode]
    return (
        parsed.hostname or "localhost",
        parsed.port or default_port,
        unquote(parsed.username) if parsed.username else None,
        unquote(parsed.password) if parsed.password else None,
        mode,
    )


def _mask(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:2]}***@{domain}" if domain else "***"


def templates() -> list[str]:
    """
    Template names on disk. The missing-text-twin test reads this.

    Files starting with `_` are partials — they have no subject and no text twin,
    because they are never sent on their own.
    """
    return sorted(
        {path.stem for path in TEMPLATE_DIR.glob("*.html") if not path.stem.startswith("_")}
    )
