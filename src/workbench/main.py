"""
The application.

`create_app()` rather than a module-level `app = FastAPI()` because tests need to
build one with different settings, and because the failure that a module-level app
causes is subtle: importing anything from `workbench.main` opens a connection
pool, so `alembic` importing the models would hold database connections, and
running the test suite would too.

The lifespan does four things, in this order, and the order is the point:

  1. Build the engine and session factory.
  2. **Verify row-level security is actually on.** If a migration added a tenant
     table without a policy, this raises and the process exits. A deployment that
     refuses to start is a five-minute incident; one that serves traffic without
     tenant isolation is a breach notification.
  3. Build the rate limiter, degrading to in-process counters if Redis is down.
  4. Log what it decided.

Shutdown disposes the engine, which waits for checked-out connections rather
than severing them — a deploy that kills in-flight requests is a deploy that
corrupts something eventually.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from workbench.admin.router import router as admin_router
from workbench.api.errors import install_handlers
from workbench.auth.router import router as auth_router
from workbench.billing.router import router as billing_router
from workbench.core.db import create_engine, create_session_factory, ping, verify_rls_active
from workbench.core.settings import Settings, get_settings
from workbench.data.router import router as documents_router
from workbench.tenancy.router import router as tenancy_router

log = logging.getLogger(__name__)

DESCRIPTION = """
Multi-tenant SaaS foundation: organisations, roles, billing, entitlements and an
append-only audit log, with tenant isolation enforced by Postgres row-level
security rather than by application filters.

Two behaviours worth knowing before you integrate:

* **403 and 402 mean different things.** 403 is a permission your role doesn't
  hold. 402 is a limit your plan doesn't include. A client that renders both as
  "you can't do that" is throwing away the only information that lets a customer
  fix it themselves.
* **Errors are RFC 7807.** `type` is a stable URI; branch on it rather than on
  the message, which is written for humans and changes.
"""


def configure_logging(settings: Settings) -> None:
    """
    Structured logs when the setting says so.

    JSON in production because logs are read by a machine first — a support
    engineer greps by request id, and `key=value` strings are a parsing problem
    for every consumer. Human-readable in development, because reading JSON in a
    terminal is a tax on the person debugging.
    """
    handler = logging.StreamHandler()
    if settings.log_json:
        handler.setFormatter(
            logging.Formatter(
                '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s",'
                '"msg":"%(message)s"}'
            )
        )
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)-7s %(name)-28s %(message)s")
        )

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level)

    # The SQL statements themselves belong in `make dev` and nowhere else: with
    # `echo=True` a query log is 10× the useful log volume and contains values.
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO
        if settings.debug and settings.environment == "development"
        else logging.WARNING
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)

    engine = create_engine(settings)
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)

    # ---- the check that has to fail loudly ------------------------------
    async with app.state.session_factory() as session:
        if await ping(session):
            unprotected = await verify_rls_active(session)
            if unprotected:
                # Refusing to start is the correct response and it is not
                # dramatic: every request served by this process would read
                # across tenants for these tables.
                await engine.dispose()
                raise RuntimeError(
                    "refusing to start: these tables carry org_id but are not protected "
                    f"by row-level security: {unprotected}. Run `make check-rls`."
                )
            log.info("row-level security verified on every tenant table")
        else:
            # A database that isn't there yet is not fatal: `up` starts the API
            # before `migrate` sometimes, and a crash loop on a cold start is
            # harder to diagnose than a health check that says so.
            log.warning("database not reachable at startup; readiness will report it")

    app.state.rate_limiter = await _build_rate_limiter(settings)

    log.info(
        "workbench started",
        extra={
            "version": settings.service_version,
            "environment": settings.environment,
            "billing": "on" if settings.billing_enabled else "off",
        },
    )
    try:
        yield
    finally:
        await engine.dispose()


async def _build_rate_limiter(settings: Settings) -> Any:
    """
    Redis when it's there, in-process counters when it isn't.

    The in-process fallback is honest about its limits — behind two replicas it
    is half a limit each — and it is still better than either refusing every
    request or having no limit at all. The log line says which one is in use, so
    "the limit isn't working in production" is one grep away rather than a
    debugging session.
    """
    from workbench.api.ratelimit import RateLimiter

    if settings.rate_limit_backend == "memory":
        log.info("rate limiting: in-process (configured)")
        return RateLimiter.in_memory()

    try:
        from redis.asyncio import Redis
    except ImportError:
        log.warning("rate limiting: in-process (the redis package is not installed)")
        return RateLimiter.in_memory()

    try:
        client = Redis.from_url(str(settings.redis_dsn), socket_connect_timeout=1, socket_timeout=1)
        # Constructing a client never connects — `Redis.from_url` is lazy, so
        # without this ping the process logs "rate limiting: redis" while every
        # single limit is failing open, and the log line is the thing you'd trust
        # when investigating why the limit isn't working. One round trip at
        # startup buys an honest answer.
        await _probe(client)
    except Exception as exc:  # noqa: BLE001
        # The reason, not the traceback. A refused connection to Redis is the
        # single most common line in a container's startup log, and forty lines
        # of redis-py internals do not make it easier to read
        # — they make the twelve other startup lines harder to find.
        log.warning(
            "rate limiting: in-process (redis did not answer)",
            extra={"redis": str(settings.redis_dsn), "reason": type(exc).__name__},
        )
        return RateLimiter.in_memory()

    log.info("rate limiting: redis")
    return RateLimiter.redis(client)


async def _probe(client: object) -> None:
    """Ping, then close. A probe connection left open is a leak per worker."""
    await client.ping()  # type: ignore[attr-defined]
    await client.aclose()  # type: ignore[attr-defined]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    app = FastAPI(
        title="workbench",
        version=settings.service_version,
        description=DESCRIPTION,
        lifespan=lifespan,
        # The docs are the API's contract with its consumers, and they're public
        # on purpose: this is what a customer's engineer reads before writing an
        # integration, and hiding them just moves the conversation to email.
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
        openapi_tags=[
            {"name": "auth", "description": "Sign-in, tokens, passwords."},
            {
                "name": "organisations",
                "description": "Orgs, members, invitations, API keys, audit.",
            },
            {"name": "billing", "description": "Plans, entitlements, Stripe."},
            {"name": "staff", "description": "Internal console. Requires `is_staff`."},
        ],
    )

    install_handlers(app)

    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable[[Request], Any]) -> Any:
        """
        One id per request, on the response and in every log line.

        Generated here rather than trusted from a header, because a client that
        can choose the id can make two requests look like one in the logs.
        """
        request_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.perf_counter()

        response: Response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{(time.perf_counter() - started) * 1000:.1f}ms"
        # No `Server` header, no framework version. Both are free reconnaissance
        # and neither helps a customer.
        if "server" in response.headers:
            del response.headers["server"]
        return response

    # Order matters only for readability here — every router is path-prefixed, so
    # none of them can shadow another. People first, then the resources an org
    # owns, then the sample resource, then billing, then the console nobody
    # should reach without a good reason.
    app.include_router(auth_router)
    app.include_router(tenancy_router)
    app.include_router(documents_router)
    app.include_router(billing_router)
    app.include_router(admin_router)

    # ---- health -----------------------------------------------------------
    # Two endpoints, because they answer different questions and conflating them
    # is how a database blip takes the whole service out of the load balancer.

    @app.get("/health/live", tags=["health"], summary="Is this process alive?")
    async def live() -> dict[str, str]:
        """
        Liveness. Always 200 if the process can answer.

        Deliberately does *not* check the database: a liveness probe that checks
        dependencies restarts every replica when the database hiccups, which
        turns a 10-second blip into a cold start.
        """
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"], summary="Should traffic come here?")
    async def ready(request: Request) -> JSONResponse:
        """
        Readiness. Checks the database, because there is nothing useful this
        process can do without it.
        """
        factory = getattr(request.app.state, "session_factory", None)
        if factory is None:
            return JSONResponse(status_code=503, content={"status": "starting"})

        async with factory() as session:
            if await ping(session):
                return JSONResponse(status_code=200, content={"status": "ok"})
        return JSONResponse(status_code=503, content={"status": "database unreachable"})

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": settings.service_version}

    return app


# `uvicorn workbench.main:app` needs a module-level object, so there is one — but
# nothing else should import it. Tests call `create_app()`.
app = create_app()


__all__ = ["app", "create_app"]
