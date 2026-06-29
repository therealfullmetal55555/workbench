"""
Cursor pagination.

`OFFSET 4000` makes the database read 4020 rows and throw 4000 away, and the page
you get is not stable: an audit log written to while you page through it shifts
every subsequent page, so a reviewer scrolling through yesterday's events can
miss one. A cursor is `(created_at, id)`, which is an index seek and a stable
position regardless of what is being written behind you.

The id is in the cursor because timestamps are not unique — two events in the
same millisecond are routine, and `WHERE created_at < $1` silently skips one of
them. The tuple is the fix, and it costs one extra `OR`.

Cursors are opaque base64 rather than a plain `?before=` timestamp, for one
reason that matters: it keeps the encoding free to change. A cursor in a URL is
a promise, and this one is not a promise anybody wants.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, and_, or_

from workbench.api.errors import BadRequest

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


@dataclass(frozen=True, slots=True)
class Cursor:
    """A position in a descending, `(created_at, id)`-ordered list."""

    created_at: datetime
    id: uuid.UUID

    def encode(self) -> str:
        raw = f"{self.created_at.isoformat()}|{self.id}"
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    @classmethod
    def decode(cls, value: str) -> Cursor:
        padded = value + "=" * (-len(value) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded.encode()).decode()
            created_at, _, identifier = raw.partition("|")
            parsed = datetime.fromisoformat(created_at)
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            # A malformed cursor is a client bug worth naming, not a 500. It is
            # also the sort of thing that arrives from a bookmark made against
            # an older API version.
            raise BadRequest("the pagination cursor is not valid") from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        try:
            identifier_uuid = uuid.UUID(identifier)
        except (ValueError, AttributeError) as exc:
            raise BadRequest("the pagination cursor is not valid") from exc
        return cls(created_at=parsed, id=identifier_uuid)


T = TypeVar("T")


@dataclass(slots=True)
class Page(Generic[T]):
    """
    One page, plus whether there is another.

    `Generic[T]` rather than PEP 695's `class Page[T]` because that syntax is
    3.12+ and the package supports 3.11. The version in `pyproject.toml` is a
    promise to whoever installs this, and a type parameter is not worth breaking
    it for.
    """

    items: list[T]
    next_cursor: str | None
    limit: int

    @property
    def has_more(self) -> bool:
        return self.next_cursor is not None

    def __iter__(self) -> Iterator[T]:  # convenience for `for row in page`
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)


def clamp_limit(limit: int | None) -> int:
    """
    Never trust a client's page size.

    `?limit=100000` is a request for the whole table over a mobile connection and
    it is always followed by a timeout. The cap is the server's opinion, and the
    client is told what it got.
    """
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(limit, MAX_LIMIT))


def apply_cursor(statement: Select, cursor: Cursor | None, *, model: object) -> Select:
    """
    Add the keyset predicate.

    Newest first: `created_at DESC, id DESC`. One extra row is fetched by the
    caller so "is there more" is answered without a `COUNT(*)` over the whole
    filtered set — which on an audit log is the query that makes the page slow.
    """
    if cursor is None:
        return statement

    return statement.where(
        or_(
            model.created_at < cursor.created_at,  # type: ignore[attr-defined]
            and_(
                model.created_at == cursor.created_at,  # type: ignore[attr-defined]
                model.id < cursor.id,  # type: ignore[attr-defined]
            ),
        )
    )


def build_page(rows: Sequence[Any], limit: int, *, field: str = "created_at") -> Page[Any]:
    """
    Turn `limit + 1` rows into a page and a cursor.

    The returned cursor points at the *last row returned*, not the extra one that
    proved there was more. Off-by-one here is the classic: it silently skips a
    row on every page boundary, and nobody notices until an audit.
    """
    has_more = len(rows) > limit
    items = list(rows[:limit])

    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = Cursor(created_at=getattr(last, field), id=last.id).encode()

    return Page(items=items, next_cursor=next_cursor, limit=limit)
