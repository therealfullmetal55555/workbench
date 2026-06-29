"""
Error handling, in one shape.

Every failure leaves this service as RFC 7807 `application/problem+json`. Not
because the RFC is beautiful, but because it forces two decisions that a bare
`{"error": "..."}` lets you skip:

  * **A stable `type` URI.** Clients branch on `type`, and it must not change
    when the message is reworded. `"not found"` as a string is a breaking change
    every time someone improves the wording.
  * **A status code that means something specific.** 403 is "your role can't do
    this"; 402 is "your plan doesn't include this". Same sentence to the
    developer, different sentence to the customer, and different conversations
    with support. They must not look alike.

Extension members carry the machine-readable detail — which limit, how much was
used, when the period ends — so a client can render "3 of 3 seats used, upgrade
to add more" without parsing English.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from workbench.billing.entitlements import FeatureNotIncluded, QuotaExceeded
from workbench.core.permissions import PermissionDenied, permissions_for

log = logging.getLogger(__name__)

# Where `type` URIs point. A docs site for the API's error vocabulary; every
# value here should have a page, because the page is where the long explanation
# goes that would otherwise bloat the response.
PROBLEM_BASE = "https://workbench.dev/problems"


class Problem(Exception):
    """Base for every error this application raises on purpose."""

    status: int = 500
    slug: str = "internal-error"
    title: str = "Internal error"

    def __init__(self, detail: str | None = None, **extra: Any) -> None:
        super().__init__(detail or self.title)
        self.detail = detail
        self.extra = {k: v for k, v in extra.items() if v is not None}

    @property
    def type_uri(self) -> str:
        return f"{PROBLEM_BASE}/{self.slug}"

    def as_dict(
        self, *, request_id: str | None = None, instance: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status,
        }
        if self.detail:
            body["detail"] = self.detail
        if instance:
            body["instance"] = instance
        if request_id:
            body["request_id"] = request_id
        body.update(self.extra)
        return body

    def headers(self) -> dict[str, str]:
        return {}


# ---------------------------------------------------------------------------
# 4xx — the caller can fix these
# ---------------------------------------------------------------------------


class BadRequest(Problem):
    status = 400
    slug = "bad-request"
    title = "Bad request"


class Unauthorized(Problem):
    status = 401
    slug = "unauthorized"
    title = "Authentication required"

    def headers(self) -> dict[str, str]:
        # Named so a client knows *what* to send. `Bearer` and not a generic
        # 401, because the API key scheme is not a browser flow.
        return {"WWW-Authenticate": 'Bearer realm="workbench", charset="UTF-8"'}


class InvalidToken(Unauthorized):
    slug = "invalid-token"
    title = "Token rejected"


class Forbidden(Problem):
    status = 403
    slug = "forbidden"
    title = "Permission denied"


class NotFound(Problem):
    status = 404
    slug = "not-found"
    title = "Not found"

    def __init__(self, resource: str = "resource", identifier: Any = None) -> None:
        # Deliberately vague about whether the row exists but belongs to someone
        # else vs doesn't exist at all. Distinguishing them is an enumeration
        # oracle over other people's ids.
        super().__init__(
            f"{resource} not found" + (f": {identifier}" if identifier is not None else ""),
            resource=resource,
        )


class Conflict(Problem):
    status = 409
    slug = "conflict"
    title = "Conflict"


class Gone(Problem):
    status = 410
    slug = "gone"
    title = "No longer available"


class ValidationFailed(Problem):
    status = 422
    slug = "validation-failed"
    title = "Validation failed"


class PaymentRequired(Problem):
    status = 402
    slug = "payment-required"
    title = "Payment required"


class TooManyRequests(Problem):
    status = 429
    slug = "rate-limited"
    title = "Too many requests"

    def __init__(self, detail: str | None = None, retry_after: int = 60, **extra: Any) -> None:
        super().__init__(detail, **extra)
        self.retry_after = retry_after

    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)}


class ServiceUnavailable(Problem):
    status = 503
    slug = "service-unavailable"
    title = "Service unavailable"


# ---------------------------------------------------------------------------
# The two that matter commercially
# ---------------------------------------------------------------------------


class QuotaExceededProblem(PaymentRequired):
    """
    402, not 403 and not 429.

    403 would say "your role can't do this" — untrue, an owner hitting a seat
    limit is exactly who can. 429 would say "try again later" — also untrue, it
    will still be full tomorrow. 402 is the only one that produces the right
    conversation: change the plan.
    """

    slug = "quota-exceeded"
    title = "Plan limit reached"


class FeatureNotIncludedProblem(PaymentRequired):
    slug = "feature-not-included"
    title = "Not included in this plan"


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def install_handlers(app: FastAPI) -> None:
    """
    Wire the handlers onto the app.

    Order matters in one place: the translation handlers for domain exceptions
    must be registered, because those exceptions are raised deep in service code
    that has no business importing FastAPI.
    """

    @app.exception_handler(Problem)
    async def _problem(request: Request, exc: Problem) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            content=exc.as_dict(request_id=_request_id(request), instance=str(request.url.path)),
            headers=exc.headers(),
            media_type="application/problem+json",
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # The default handler returns `{"detail": [...]}`, which is a different
        # shape from every other error in the API. Clients should not need two
        # parsers for one service.
        problem = ValidationFailed(
            "one or more fields are invalid",
            errors=[
                {
                    "field": ".".join(str(part) for part in error.get("loc", ())[1:]),
                    "message": error.get("msg", ""),
                    "type": error.get("type", ""),
                }
                for error in exc.errors()
            ],
        )
        return JSONResponse(
            status_code=problem.status,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # A framework 404 or 405 has to come out in the same shape as ours, or a
        # client that parses problem details gets a plain `{"detail": ...}` for
        # the one case nobody tested.
        mapping: dict[int, tuple[type[Problem], str]] = {
            401: (Unauthorized, "unauthorized"),
            403: (Forbidden, "forbidden"),
            404: (NotFound, "not-found"),
            405: (Conflict, "method-not-allowed"),
        }
        cls, slug = mapping.get(exc.status_code, (Problem, f"http-{exc.status_code}"))
        detail = exc.detail if isinstance(exc.detail, str) else None
        problem = cls(detail)
        if cls is Problem:
            problem.status = exc.status_code
            problem.slug = slug
            problem.title = f"HTTP {exc.status_code}"
        return JSONResponse(
            status_code=exc.status_code,
            content=problem.as_dict(request_id=_request_id(request)),
            headers=getattr(exc, "headers", None) or {},
            media_type="application/problem+json",
        )

    # ------------------------------------------------------------------
    # Domain exceptions, translated once, here
    # ------------------------------------------------------------------
    # `core.permissions` and `billing.entitlements` raise plain Python
    # exceptions. They don't import FastAPI and they don't know what a status
    # code is — which is why they're testable in a tenth of a second, and why
    # this is the only place that has to know they mean 403 and 402.

    @app.exception_handler(PermissionDenied)
    async def _permission_denied(request: Request, exc: PermissionDenied) -> JSONResponse:
        problem = Forbidden(
            f"role '{exc.role}' does not hold permission '{exc.permission}'",
            role=exc.role,
            permission=exc.permission,
            # The console renders buttons from this list instead of guessing
            # which ones would 403 — the alternative is a UI that offers actions
            # and then refuses them.
            granted=sorted(permissions_for(exc.role)),
        )
        return JSONResponse(
            status_code=problem.status,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )

    @app.exception_handler(QuotaExceeded)
    async def _quota(request: Request, exc: QuotaExceeded) -> JSONResponse:
        problem = QuotaExceededProblem(
            f"{exc.entitlement} limit reached on the {exc.plan} plan ({exc.used}/{exc.limit})",
            plan=exc.plan,
            entitlement=exc.entitlement,
            limit=exc.limit,
            used=exc.used,
        )
        return JSONResponse(
            status_code=problem.status,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )

    @app.exception_handler(FeatureNotIncluded)
    async def _feature(request: Request, exc: FeatureNotIncluded) -> JSONResponse:
        problem = FeatureNotIncludedProblem(
            f"{exc.feature} is not included in the {exc.plan} plan",
            feature=exc.feature,
            plan=exc.plan,
        )
        return JSONResponse(
            status_code=problem.status,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )

    @app.exception_handler(ValueError)
    async def _value_error(request: Request, exc: ValueError) -> JSONResponse:
        # Every deliberate ValueError in this codebase is a domain rule refusing
        # a value: a reserved slug, an invitation that is no longer pending, a
        # password that is too short. They are raised where the rule lives, so
        # the rule is one line away from the thing it constrains. Catching them
        # here is what keeps that readable instead of returning 500s.
        problem = ValidationFailed(str(exc))
        return JSONResponse(
            status_code=problem.status,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log it loudly with the request id, return nothing useful to the caller.
        # A stack trace in a response body is a free map of the internals.
        log.exception("unhandled error", extra={"request_id": _request_id(request)})
        problem = Problem("the request failed; the error has been logged with the request id")
        return JSONResponse(
            status_code=500,
            content=problem.as_dict(request_id=_request_id(request)),
            media_type="application/problem+json",
        )
