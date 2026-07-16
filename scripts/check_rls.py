#!/usr/bin/env python3
"""
Fail the build if a tenant table could leak.

Run in CI after migrations, and locally before you push a migration that adds a
table. It answers four questions, in order of how much they'd cost you:

  1. Does every table with an `org_id` column have RLS *and* FORCE?
  2. Does every one of those tables actually have a policy?
  3. Does each policy reference the session setting, rather than comparing to
     something that is always true?
  4. Does the application role own anything? If it does, RLS is optional for it
     and the whole design is decorative.

Exit code is the number of problems, capped at 1 for CI's benefit.

    python scripts/check_rls.py                       # uses DATABASE_ADMIN_DSN
    python scripts/check_rls.py --dsn postgresql://…
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import dataclass

try:
    import asyncpg
except ImportError:  # pragma: no cover
    asyncpg = None  # type: ignore[assignment]

RED, GREEN, YELLOW, DIM, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"

TENANT_COLUMN = "org_id"
APP_ROLE = os.getenv("APP_DB_ROLE", "workbench")
TENANT_SETTING = "app.current_org"

# Tables that carry `org_id` and are deliberately not protected, with the reason.
# An exemption here is a written decision somebody has to defend in review, which
# is the difference between this and a table nobody remembered to protect.
EXEMPT: dict[str, str] = {
    "stripe_events": (
        "the idempotency ledger. Events are recorded before the org is resolved — "
        "that is what makes a webhook retry safe — so a tenant-keyed policy cannot "
        "apply to the insert. Read only by the webhook path, always by event_id."
    ),
}


@dataclass
class Finding:
    severity: str  # "error" | "warn"
    table: str
    message: str

    def render(self) -> str:
        colour = RED if self.severity == "error" else YELLOW
        return f"  {colour}{self.severity}{RESET}  {self.table}: {self.message}"


QUERIES = {
    # Every table that carries org_id, and whether RLS is on for it.
    "tenant_tables": f"""
        SELECT c.relname                AS table_name,
               c.relrowsecurity         AS rls_enabled,
               c.relforcerowsecurity    AS rls_forced,
               pg_get_userbyid(c.relowner) AS owner
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind = 'r'
           AND EXISTS (
                 SELECT 1 FROM information_schema.columns col
                  WHERE col.table_schema = 'public'
                    AND col.table_name = c.relname
                    AND col.column_name = '{TENANT_COLUMN}'
               )
         ORDER BY c.relname
    """,
    # Policies per table, with the expression so we can check it's real.
    "policies": """
        SELECT c.relname AS table_name,
               p.polname  AS policy_name,
               p.polcmd   AS command,
               pg_get_expr(p.polqual, p.polrelid)      AS using_expression,
               pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
          FROM pg_policy p
          JOIN pg_class c ON c.oid = p.polrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
         ORDER BY c.relname, p.polname
    """,
    "app_role": """
        SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
          FROM pg_roles
         WHERE rolname = $1
    """,
    "table_owners": """
        SELECT tablename, tableowner
          FROM pg_tables
         WHERE schemaname = 'public'
    """,
}


def _command(raw: object) -> str:
    """`polcmd` arrives as bytes; the rest of this file compares against letters."""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode()
    return str(raw)


async def inspect(dsn: str) -> tuple[list[Finding], dict[str, int]]:
    if asyncpg is None:
        print(f"{RED}asyncpg is required: pip install asyncpg{RESET}", file=sys.stderr)
        raise SystemExit(2)

    findings: list[Finding] = []
    stats: dict[str, int] = {}

    connection = await asyncpg.connect(dsn.replace("postgresql+asyncpg", "postgresql"))
    try:
        tables = await connection.fetch(QUERIES["tenant_tables"])
        policies = await connection.fetch(QUERIES["policies"])
        owners = {row["tableowner"] for row in await connection.fetch(QUERIES["table_owners"])}

        app_role = await connection.fetchrow(QUERIES["app_role"], APP_ROLE)

        stats["tenant_tables"] = len(tables)
        stats["policies"] = len(policies)

        if app_role is None:
            findings.append(Finding("warn", APP_ROLE, "application role does not exist"))
        else:
            if app_role["rolsuper"]:
                findings.append(
                    Finding("error", APP_ROLE, "role is SUPERUSER — RLS does not apply")
                )
            if app_role["rolbypassrls"]:
                findings.append(
                    Finding("error", APP_ROLE, "role has BYPASSRLS — RLS does not apply")
                )
            if app_role["rolcreaterole"] or app_role["rolcreatedb"]:
                findings.append(
                    Finding("warn", APP_ROLE, "role can create roles/databases; it needs neither")
                )

        if not tables:
            findings.append(Finding("warn", "—", "no tenant tables found; did the migrations run?"))

        by_table: dict[str, list] = {}
        for policy in policies:
            by_table.setdefault(policy["table_name"], []).append(policy)

        for table in tables:
            name = table["table_name"]

            if name in EXEMPT:
                stats.setdefault("exempt", 0)
                stats["exempt"] += 1
                continue

            if not table["rls_enabled"]:
                findings.append(Finding("error", name, "ENABLE ROW LEVEL SECURITY is missing"))
            if not table["rls_forced"]:
                # The subtle one. Without FORCE, policies stop applying the
                # moment the connecting role owns the table.
                findings.append(Finding("error", name, "FORCE ROW LEVEL SECURITY is missing"))
            if table["owner"] == APP_ROLE:
                findings.append(
                    Finding("error", name, f"owned by {APP_ROLE} — the app must not own tables")
                )
            elif table["owner"] in owners:
                pass  # owned by the migration role, which is what we want

            table_policies = by_table.get(name, [])
            if not table_policies:
                findings.append(
                    Finding(
                        "error", name, "no policy attached — table is unreadable or unprotected"
                    )
                )
                continue

            # asyncpg hands back `polcmd` (a Postgres "char") as bytes, not str.
            # Comparing b'*' to '*' is silently always false, which turns every
            # table into a false "no SELECT policy" warning — and a check that
            # cries wolf on everything gets ignored, which is worse than not
            # having it.
            commands = {_command(p["command"]) for p in table_policies}
            has_select = bool(commands & {"r", "*"})
            has_insert = bool(commands & {"a", "*"})
            has_write_check = any(p["check_expression"] for p in table_policies)

            if not has_select:
                findings.append(Finding("warn", name, "no SELECT policy — the app can't read it"))
            if has_insert and not has_write_check:
                # USING governs reads; WITH CHECK governs writes. A policy with
                # only USING lets rows be inserted into any tenant.
                findings.append(
                    Finding(
                        "error",
                        name,
                        "insert path has no WITH CHECK — rows can be written cross-tenant",
                    )
                )

            for policy in table_policies:
                expression = (
                    f"{policy['using_expression'] or ''} {policy['check_expression'] or ''}"
                )
                if TENANT_COLUMN in expression and "current_setting" not in expression:
                    findings.append(
                        Finding(
                            "error",
                            name,
                            f"policy {policy['policy_name']} compares {TENANT_COLUMN} to something "
                            "other than the session setting",
                        )
                    )

        # An `organizations`-like table legitimately has many policies; report
        # them so a reviewer can see the shape without opening psql.
        stats["tables_with_multiple_policies"] = sum(
            1 for name, plist in by_table.items() if len(plist) > 1
        )
    finally:
        await connection.close()

    return findings, stats


async def main() -> int:
    parser = argparse.ArgumentParser(description="Audit row-level security on tenant tables")
    parser.add_argument(
        "--dsn",
        default=os.getenv(
            "DATABASE_ADMIN_DSN",
            "postgresql://workbench_admin:workbench_admin@localhost:5433/workbench",
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="only print findings")
    args = parser.parse_args()

    try:
        findings, stats = await inspect(args.dsn)
    except OSError as exc:
        print(f"{RED}cannot reach postgres: {exc}{RESET}", file=sys.stderr)
        print(f"{DIM}start it with `make up`{RESET}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(
            f"{DIM}checked {stats.get('tenant_tables', 0)} tenant tables, "
            f"{stats.get('policies', 0)} policies{RESET}"
        )
        for table, reason in sorted(EXEMPT.items()):
            print(f"{DIM}  exempt  {table}: {reason}{RESET}")

    for finding in findings:
        print(finding.render())

    errors = [f for f in findings if f.severity == "error"]
    if errors:
        print(f"{RED}check_rls: {len(errors)} problem(s) that can leak data{RESET}")
        return 1

    warnings = len(findings)
    note = f" ({warnings} warning(s))" if warnings else ""
    print(f"{GREEN}check_rls: ok{RESET}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
