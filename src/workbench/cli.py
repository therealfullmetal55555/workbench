"""
The `workbench` command.

A thin wrapper over the things you do to a running instance, so that the
answer to "how do I make my account staff" is a command rather than a paragraph
in a README with a psql snippet in it. Commands that touch a database refuse to
do anything interesting in production unless you say `--yes`, for the same reason
`make seed` refuses: the person typing has root, and the mistake is one tab
completion away.

    workbench serve --reload
    workbench check-rls
    workbench plans
    workbench matrix
    workbench grant-staff you@example.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC

from sqlalchemy import select, text

from workbench.core.db import create_engine, create_session_factory
from workbench.core.settings import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="workbench", description=__doc__.split("\n")[1])
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    sub.add_parser("version", help="print the version")
    sub.add_parser("plans", help="print the plan catalogue")
    sub.add_parser("matrix", help="print the permission matrix")
    sub.add_parser("check-rls", help="audit row-level security (needs a database)")

    grant = sub.add_parser("grant-staff", help="give a user staff access")
    grant.add_argument("email")
    grant.add_argument("--revoke", action="store_true", help="take it away instead")
    grant.add_argument("--yes", action="store_true", help="needed outside development")

    args = parser.parse_args(argv)

    if args.command == "serve":
        import uvicorn

        uvicorn.run(
            "workbench.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            proxy_headers=True,  # behind a load balancer; see api/deps.client_ip
        )
        return 0

    if args.command == "version":
        settings = get_settings()
        print(f"workbench {settings.service_version} ({settings.environment})")
        return 0

    if args.command == "plans":
        import json

        from workbench.billing.entitlements import all_plans

        print(json.dumps(all_plans(), indent=2))
        return 0

    if args.command == "matrix":
        from workbench.core.permissions import describe_matrix

        for row in describe_matrix():
            roles = row["roles"]
            print(f"  {row['permission']:22} {', '.join(str(role) for role in roles)}")
        return 0

    if args.command == "check-rls":
        import subprocess
        from pathlib import Path

        script = Path(__file__).resolve().parent.parent.parent / "scripts" / "check_rls.py"
        if not script.exists():  # installed as a wheel, no repo around it
            print("scripts/check_rls.py not found — run this from a checkout", file=sys.stderr)
            return 2
        return subprocess.call([sys.executable, str(script)])

    if args.command == "grant-staff":
        return asyncio.run(_grant_staff(args.email, revoke=args.revoke, confirmed=args.yes))

    return 1


async def _grant_staff(email: str, *, revoke: bool, confirmed: bool) -> int:
    from datetime import datetime

    from workbench.auth.models import User

    settings = get_settings()
    if settings.is_production and not confirmed:
        print(
            "refusing to change staff access in production without --yes.\n"
            "This is the flag that turns one compromised account into access to every "
            "customer's data.",
            file=sys.stderr,
        )
        return 1

    engine = create_engine(settings)
    factory = create_session_factory(engine)
    try:
        async with factory() as session, session.begin():
            # Staff access is a cross-tenant read, so this one command runs
            # with the maintenance setting rather than through a policy that
            # a user could ever exercise.
            await session.execute(text("SELECT set_config('app.maintenance', 'on', true)"))
            user = (
                await session.execute(select(User).where(User.email == User.normalise_email(email)))
            ).scalar_one_or_none()
            if user is None:
                print(f"no such user: {email}", file=sys.stderr)
                return 1

            user.is_staff = not revoke
            user.staff_since = None if revoke else (user.staff_since or datetime.now(UTC))
            action = "revoked" if revoke else "granted"
            print(f"{action}: {user.email} (is_staff={user.is_staff})")
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
