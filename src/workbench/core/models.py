"""
Model base and mixins.

Conventions the whole codebase relies on:

* Primary keys are UUIDv7-ish: time-ordered, so index inserts stay near the end
  of the B-tree instead of scattering across it the way v4 does. Generated in
  Python because Postgres 16 has no `uuidv7()` built in and adding an extension
  for it is worse than twenty lines here.
* Every tenant-owned table carries `org_id` — that exact column name, because
  the RLS policies, the migration helper and the CI check all look for it.
* Timestamps are timezone-aware, always. A naive `created_at` in a product with
  customers in three timezones is a bug that surfaces in a support ticket.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

# Explicit naming convention. Without it, Alembic autogenerate produces
# migrations that can't drop the constraints it created, because it never knew
# what they were called.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def to_dict(self) -> dict[str, Any]:
        return {column.key: getattr(self, column.key) for column in self.__table__.columns}

    def __repr__(self) -> str:
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} {pk}>"


def uuid7() -> uuid.UUID:
    """
    UUIDv7: 48 bits of millisecond timestamp, then randomness.

    Slightly more code than `uuid4()` and worth it — v4 keys are random, so every
    insert lands in a random page of the index. On a table that grows, that's
    constant page splits and a cache that never helps.
    """
    millis = int(time.time() * 1000)
    rand_a = uuid.uuid4().int >> 64 & 0x0FFF
    rand_b = uuid.uuid4().int & ((1 << 62) - 1)

    value = (millis & 0xFFFFFFFFFFFF) << 80
    value |= 0x7 << 76  # version 7
    value |= rand_a << 64
    value |= 0b10 << 62  # variant
    value |= rand_b
    return uuid.UUID(int=value)


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid7,
        sort_order=-100,
    )


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        sort_order=100,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
        sort_order=101,
    )


class TenantScoped:
    """
    Marks a table as belonging to one organisation.

    The `org_id` column name is load-bearing: `alembic` helper functions, the
    `check_rls` script, and every policy in the migrations match on it literally.
    Renaming it per table would mean hand-writing each policy, and one of them
    would be wrong.
    """

    @declared_attr
    @classmethod
    def org_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(
            PGUUID(as_uuid=True),
            ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
            sort_order=-50,
        )


class SoftDelete:
    """
    Deletion that a customer can undo, without a `deleted` boolean scattered
    through every query.

    Readable rows have `deleted_at IS NULL`. A partial index keeps that cheap.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, index=True, sort_order=102
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def soft_delete(self) -> None:
        self.deleted_at = datetime.now(UTC)


def is_test_environment() -> bool:
    return os.getenv("ENVIRONMENT", "development") in {"test", "development"}
