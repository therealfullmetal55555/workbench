#!/usr/bin/env bash
#
# Build dist/workbench-<version>.tar.gz
#
# A tarball you can untar onto a machine with Docker and a database and have
# running: the application, the migrations, the fixtures, the tests and the
# documents that explain the decisions. Nothing in here needs a git checkout.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep -m1 '^version' pyproject.toml | cut -d'"' -f2)"
NAME="workbench-${VERSION}"
OUT="$ROOT/dist"
STAGE="$(mktemp -d)"
TARGET="$STAGE/$NAME"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

echo "packaging $NAME"

mkdir -p "$TARGET" "$OUT"

INCLUDE=(
  README.md
  SPEC.md
  CHANGELOG.md
  LICENSE
  Makefile
  pyproject.toml
  pytest.ini
  alembic.ini
  docker-compose.yml
  .env.example
  docker
  docs
  migrations
  scripts
  src
  tests
)

for entry in "${INCLUDE[@]}"; do
  if [ -e "$entry" ]; then
    cp -R "$entry" "$TARGET/"
  else
    echo "  skip (not present): $entry"
  fi
done

# Nothing generated, nothing cached, and above all no .env: the tarball is
# handed around, and a committed .env is a committed JWT secret.
find "$TARGET" -type d \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache \
  -o -name .mypy_cache -o -name .venv -o -name dist \) -prune -exec rm -rf {} +
find "$TARGET" -type f \( -name '*.pyc' -o -name '.env' -o -name '*.log' \) -delete
rm -f "$TARGET/alembic.ini.bak"

cat > "$TARGET/INSTALL.txt" <<'EOF'
workbench
=========

A multi-tenant SaaS foundation: organisations, roles, invitations, billing,
entitlements, an append-only audit log and a staff console.

Quick start with Docker
-----------------------
    cp .env.example .env
    python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(48))" >> .env
    make up                  # postgres, redis, mailhog, api, worker
    make migrate
    make seed
    open http://localhost:8000/docs

Without Docker (what the tests do)
----------------------------------
    createdb workbench && createdb workbench_test
    psql -c "CREATE ROLE workbench LOGIN PASSWORD 'workbench' NOSUPERUSER"
    psql -c "CREATE ROLE workbench_admin LOGIN PASSWORD 'workbench_admin' SUPERUSER"
    DATABASE_ADMIN_DSN=postgresql+asyncpg://workbench_admin:workbench_admin@localhost:5432/workbench \
        python -m alembic upgrade head
    make seed

    # The application role must NOT own any table, or RLS stops applying to it.
    # `make check-rls` fails the build if that has happened.

Verify before you trust it
--------------------------
    make test           unit tests, no database
    make test-db        isolation + HTTP suites against a live Postgres
    make check-rls      every tenant table has FORCE RLS and a policy
    make lint type      ruff and mypy, both clean

Where the reasoning lives
-------------------------
    docs/TENANCY.md     why isolation is in Postgres, and what FORCE costs
    docs/BILLING.md     webhook idempotency, out-of-order delivery, dunning
    docs/DEMO.md        a walkthrough with real request and response bodies
    CHANGELOG.md        ten defects that only appeared when the stack ran

Credentials after `make seed`: every account uses `correct-horse-battery-staple`.
`staff@workbench.test` is the only account with console access, and it is a
member of no organisation.
EOF

tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"

# A file list makes two builds diffable without unpacking both.
( cd "$TARGET" && find . -type f | LC_ALL=C sort | sed 's|^\./||' ) > "$OUT/$NAME.filelist.txt"

SIZE="$(du -h "$OUT/$NAME.tar.gz" | cut -f1)"
FILES="$(wc -l < "$OUT/$NAME.filelist.txt" | tr -d ' ')"
echo "wrote $OUT/$NAME.tar.gz  ($SIZE, $FILES files)"
