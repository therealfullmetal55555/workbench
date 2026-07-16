#!/usr/bin/env python3
"""
Development fixtures.

Refuses to run outside development. A seed script that can be pointed at
production is a seed script that eventually will be, and the failure mode is
"every customer's data replaced with Acme and Beta Co".

    make seed
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from workbench.auth.passwords import hash_password  # noqa: E402
from workbench.core.settings import get_settings  # noqa: E402

DEV_PASSWORD = "correct-horse-battery-staple"

# email, name, is_staff.
#
# `is_staff` is support access to the *console*: reading across customers,
# overriding a plan, impersonating. Exactly one account has it, and it is not a
# member of any organisation — the two are different things, and a fixture that
# merges them teaches the wrong shape to everyone who copies it. The first
# version of this list had the flag on Acme's owner and off the account called
# "staff", so the demo could not reach the console and a customer's owner could.
USERS = [
    ("owner@acme.test", "Ada Owner", False),
    ("admin@acme.test", "Ben Admin", False),
    ("member@beta.test", "Cleo Member", False),
    ("staff@workbench.test", "Dana Staff", True),
]

# slug, name, plan, monthly requests used.
#
# No seat count here, deliberately: seats are *counted* from the memberships
# below rather than stored, because a stored counter is the thing that drifts —
# and it drifts upward in the customer's favour, which is the direction nobody
# reports. The membership list is the seat usage.
ORGS = [
    ("acme", "Acme Corporation", "team", 42_000),
    ("beta-co", "Beta Co", "free", 940),
]


async def main() -> int:
    settings = get_settings()
    if settings.environment not in {"development", "test"}:
        print(f"refusing to seed with ENVIRONMENT={settings.environment}", file=sys.stderr)
        return 1

    engine = create_async_engine(str(settings.postgres_admin_dsn))
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session, session.begin():
        # Seeding twice has to be a no-op, not a stack trace.
        #
        # The first version generated a fresh uuid per fixture and used it for the
        # rows that reference the user or the org. `ON CONFLICT DO NOTHING` then
        # kept the row from the first run, the second run's foreign keys pointed
        # at ids that were never inserted, and `make seed` failed with a foreign
        # key violation on a machine where it had already worked once — which
        # reads as a broken script rather than a script that isn't idempotent.
        #
        # `DO UPDATE SET <something harmless>` is what makes `RETURNING` fire for
        # an existing row: `DO NOTHING` returns no rows at all, so there would be
        # nothing to read back.
        ids: dict[str, uuid.UUID] = {}
        for email, name, is_staff in USERS:
            user_id = (
                await session.execute(
                    text("""
                        INSERT INTO users (id, email, name, password_hash, is_staff,
                                           staff_since, email_verified_at)
                        VALUES (:id, :email, :name, :hash, :staff, :staff_since, now())
                        ON CONFLICT ((lower(email))) DO UPDATE SET name = EXCLUDED.name
                        RETURNING id
                        """),
                    {
                        "id": uuid.uuid4(),
                        "email": email,
                        "name": name,
                        # A fresh hash every run, deliberately: argon2 salts, so
                        # two runs produce different strings for the same
                        # password and a diff of the database is unreadable.
                        "hash": hash_password(DEV_PASSWORD),
                        "staff": is_staff,
                        "staff_since": datetime.now(UTC) if is_staff else None,
                    },
                )
            ).scalar_one()
            ids[email] = user_id

        for slug, name, plan, requests in ORGS:
            period_start = datetime.now(UTC).replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            org_id = (
                await session.execute(
                    text("""
                        INSERT INTO organizations (id, name, slug, is_active, billing_customer_id)
                        VALUES (:id, :name, :slug, true, :customer)
                        ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
                        RETURNING id
                        """),
                    {
                        "id": uuid.uuid4(),
                        "name": name,
                        "slug": slug,
                        "customer": f"cus_dev_{slug}",
                    },
                )
            ).scalar_one()
            ids[slug] = org_id

            await session.execute(
                text("""
                        INSERT INTO usage_records (id, org_id, meter, period_start, period_end,
                                                   quantity, included)
                        VALUES (:id, :org, 'requests', :start, :end, :qty, :included)
                        ON CONFLICT ON CONSTRAINT uq_usage_records_org_id_meter_period_start
                        DO UPDATE SET quantity = EXCLUDED.quantity
                        """),
                {
                    "id": uuid.uuid4(),
                    "org": org_id,
                    "start": period_start,
                    "end": period_start + timedelta(days=30),
                    "qty": requests,
                    "included": 100_000 if plan == "team" else 1_000,
                },
            )

        memberships = [
            ("owner@acme.test", "acme", "owner"),
            ("admin@acme.test", "acme", "admin"),
            ("member@beta.test", "beta-co", "member"),
        ]
        for email, slug, role in memberships:
            await session.execute(
                text("""
                        INSERT INTO memberships (id, org_id, user_id, role)
                        VALUES (:id, :org, :user, :role)
                        ON CONFLICT ON CONSTRAINT uq_memberships_user_id_org_id DO NOTHING
                        """),
                {"id": uuid.uuid4(), "org": ids[slug], "user": ids[email], "role": role},
            )

        for i in range(1, 4):
            # `ON CONFLICT` on nothing: documents have no natural key, so the
            # second run would otherwise add three more. Deleting this org's
            # documents first is the honest version of "make the fixture match
            # this file", and it is safe because the seed is development-only.
            await session.execute(
                text(
                    "DELETE FROM documents WHERE org_id = :org "
                    "AND title LIKE 'Acme internal document%'"
                ),
                {"org": ids["acme"]},
            )
            await session.execute(
                text("""
                        INSERT INTO documents (id, org_id, title, body, created_by_id)
                        VALUES (:id, :org, :title, :body, :author)
                        """),
                {
                    "id": uuid.uuid4(),
                    "org": ids["acme"],
                    "title": f"Acme internal document {i}",
                    "body": "This row is only visible to Acme.",
                    "author": ids["owner@acme.test"],
                },
            )

        await session.execute(
            text("DELETE FROM invitations WHERE org_id = :org AND email = 'newcomer@acme.test'"),
            {"org": ids["acme"]},
        )
        await session.execute(
            text("""
                    INSERT INTO invitations (id, org_id, email, role, token_hash,
                                             expires_at, invited_by_id)
                    VALUES (:id, :org, :email, 'member', :hash, :expires, :inviter)
                    """),
            {
                "id": uuid.uuid4(),
                "org": ids["acme"],
                "email": "newcomer@acme.test",
                "hash": "dev-only-not-a-real-hash",
                "expires": datetime.now(UTC) + timedelta(hours=72),
                "inviter": ids["owner@acme.test"],
            },
        )

    await engine.dispose()

    print("seeded two organisations, four users, three documents, one invitation")
    print()
    print("  email                     password                        org        role")
    print("  ------------------------  ------------------------------  ---------  --------")
    print(f"  owner@acme.test           {DEV_PASSWORD}   acme       owner")
    print(f"  admin@acme.test           {DEV_PASSWORD}   acme       admin")
    print(f"  member@beta.test          {DEV_PASSWORD}   beta-co    member")
    print("  staff@workbench.test      (staff, no org)                 —          staff")
    print()
    print("  Beta Co is at 94% of its free-tier request quota — the near-quota path")
    print("  is seeded deliberately, because that is the state nobody tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
