"""
Configuration, loaded once and validated on import.

Two rules, both learned the hard way:

1. Anything that must not be wrong in production raises at startup, not at first
   use. A missing Stripe secret should stop the deploy, not surface as a 500 on
   the pricing page.
2. Defaults are for development only. Every production-critical setting is
   Optional with no default, and `validate_production()` refuses to boot without it.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- identity ----------------------------------------------------------
    environment: Environment = "development"
    service_name: str = "workbench"
    service_version: str = "0.1.0"
    debug: bool = False
    api_base_url: str = "http://localhost:8000"
    app_base_url: str = "http://localhost:3000"

    # ---- database ----------------------------------------------------------
    # Both names are accepted, and that is deliberate rather than lazy: the
    # settings attribute reads better as `postgres_dsn`, while every other file
    # in the repo — .env.example, compose, CI — says DATABASE_DSN. An alias is
    # cheaper than the bug where a deployment sets DATABASE_DSN, the app
    # silently falls back to the localhost default, and the only symptom is
    # that production is pointed at the wrong database.
    postgres_dsn: PostgresDsn = Field(  # type: ignore[assignment]
        default="postgresql+asyncpg://workbench:workbench@localhost:5432/workbench",
        validation_alias=AliasChoices("DATABASE_DSN", "POSTGRES_DSN"),
        description=(
            "Async DSN used by the app. Must NOT be a superuser — RLS is bypassed by owners."
        ),
    )
    postgres_admin_dsn: PostgresDsn = Field(  # type: ignore[assignment]
        default="postgresql+asyncpg://workbench_admin:workbench_admin@localhost:5432/workbench",
        validation_alias=AliasChoices("DATABASE_ADMIN_DSN", "POSTGRES_ADMIN_DSN"),
        description="Used by migrations only. Owning role, bypasses RLS.",
    )
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_recycle_seconds: int = 1800
    db_statement_timeout_ms: int = 15_000
    redis_dsn: RedisDsn = "redis://localhost:6379/0"  # type: ignore[assignment]

    # "auto" tries Redis and falls back to per-process counters; "memory" skips
    # the attempt. Tests set it to "memory": a suite that opens a Redis
    # connection it knows is closed spends most of its output on tracebacks.
    rate_limit_backend: Literal["auto", "memory"] = "auto"

    # ---- auth --------------------------------------------------------------
    jwt_secret: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    # A refresh token reused after rotation means the token leaked. How long to
    # keep the old row so we can detect it instead of just failing the request.
    refresh_reuse_grace_seconds: int = 0
    password_min_length: int = 12
    api_key_prefix: str = "wb"

    # ---- invitations -------------------------------------------------------
    invitation_ttl_hours: int = 72
    invitation_max_pending_per_org: int = 50

    # ---- billing -----------------------------------------------------------
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_price_ids: dict[str, str] = Field(default_factory=dict)
    billing_enabled: bool = True
    # Webhooks arrive before the browser returns from Checkout. If we can't find
    # the org for a customer, retry rather than dropping money on the floor.
    webhook_max_attempts: int = 8
    usage_soft_warn_ratio: float = 0.8

    # ---- email -------------------------------------------------------------
    smtp_url: str | None = None
    mail_from: str = "workbench <hello@workbench.test>"

    # ---- observability -----------------------------------------------------
    otel_enabled: bool = False
    otel_endpoint: str = "http://localhost:4317"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    # ---- admin -------------------------------------------------------------
    impersonation_max_minutes: int = 60

    @field_validator("postgres_dsn", "postgres_admin_dsn")
    @classmethod
    def _must_be_async(cls, value: PostgresDsn) -> PostgresDsn:
        if "+asyncpg" not in str(value):
            raise ValueError(
                "DSN must use the asyncpg driver (postgresql+asyncpg://...). "
                "The sync driver silently blocks the event loop under load."
            )
        return value

    @model_validator(mode="after")
    def _validate_production(self) -> Settings:
        if self.environment != "production":
            return self

        problems: list[str] = []

        if self.debug:
            problems.append("DEBUG must be false in production")
        if "localhost" in str(self.postgres_dsn) or "localhost" in str(self.redis_dsn):
            problems.append("DATABASE and REDIS must not point at localhost in production")
        if self.jwt_secret and len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET must be at least 32 characters in production")
        if self.billing_enabled:
            if not self.stripe_secret_key:
                problems.append("STRIPE_SECRET_KEY is required when billing is enabled")
            if not self.stripe_webhook_secret:
                problems.append("STRIPE_WEBHOOK_SECRET is required when billing is enabled")

        # The single most dangerous misconfiguration in this system: connecting
        # as the role that owns the tables turns row-level security off.
        if str(self.postgres_dsn) == str(self.postgres_admin_dsn):
            problems.append(
                "the app and migration DSNs are identical — the app would run as the "
                "table owner and RLS would not apply"
            )

        if problems:
            raise RuntimeError("invalid production configuration:\n  - " + "\n  - ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_test(self) -> bool:
        return self.environment == "test"

    def stripe_price_for(self, plan_code: str) -> str | None:
        return self.stripe_price_ids.get(plan_code)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
