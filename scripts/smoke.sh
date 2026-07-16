#!/usr/bin/env bash
#
# End-to-end smoke test against a running API.
#
#   scripts/smoke.sh [base-url]        default: http://localhost:8000
#
# This is not a substitute for `pytest tests/test_api.py` — it is what runs in CI
# against a freshly started server, and what you run after a deploy. It walks the
# path a new customer walks: sign up, sign in, create an org, write something,
# read it back. If any of that breaks, the deploy is bad and you know before the
# first support ticket.
#
# Everything is asserted on the *status codes and the returned ids*, not on the
# response bodies: a test that greps prose fails the day somebody improves a
# message, and nobody ever goes back to fix it.

set -euo pipefail

BASE="${1:-http://localhost:8000}"
EMAIL="smoke-${RANDOM}-$(date +%s)@example.com"
PASSWORD="correct-horse-battery-staple"

say()  { printf '  %-46s %s\n' "$1" "$2"; }
fail() { printf '\n  FAILED: %s\n' "$1" >&2; exit 1; }

# code <expected> <description> <curl args...>
code() {
  local expected="$1" description="$2"; shift 2
  local actual
  actual="$(curl -s -o /tmp/smoke.body -w '%{http_code}' "$@")"
  if [ "$actual" != "$expected" ]; then
    say "$description" "$actual (expected $expected)"
    printf '\n  body: %s\n' "$(head -c 400 /tmp/smoke.body)" >&2
    fail "$description"
  fi
  say "$description" "$actual"
}

json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "smoke test against $BASE"

code 200 "GET  /health/live"   "$BASE/health/live"
code 200 "GET  /health/ready"  "$BASE/health/ready"
code 200 "GET  /plans (public)" "$BASE/plans"

# --- sign up -----------------------------------------------------------------
code 202 "POST /auth/signup" \
  -X POST "$BASE/auth/signup" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Smoke Test\"}"

# The same address again must be indistinguishable from the first request. This
# is the property the endpoint exists for, and it is one line to check.
code 202 "POST /auth/signup (repeat address)" \
  -X POST "$BASE/auth/signup" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Smoke Test\"}"

code 401 "POST /auth/login (wrong password)" \
  -X POST "$BASE/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"definitely-not-the-password\"}"

code 200 "POST /auth/login" \
  -X POST "$BASE/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"

TOKEN="$(json '["access_token"]' < /tmp/smoke.body)"
AUTH="authorization: Bearer $TOKEN"

code 200 "GET  /auth/me" -H "$AUTH" "$BASE/auth/me"

# --- the tenant --------------------------------------------------------------
code 201 "POST /orgs" -X POST "$BASE/orgs" -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"Smoke Co $RANDOM\"}"

ORG="$(json '["id"]' < /tmp/smoke.body)"

code 200 "GET  /orgs" -H "$AUTH" "$BASE/orgs"
code 200 "GET  /orgs/{id}/entitlements" -H "$AUTH" "$BASE/orgs/$ORG/entitlements"

code 201 "POST /orgs/{id}/documents" -X POST "$BASE/orgs/$ORG/documents" -H "$AUTH" \
  -H 'content-type: application/json' -d '{"title":"smoke","body":"written by scripts/smoke.sh"}'

DOC="$(json '["id"]' < /tmp/smoke.body)"

code 200 "GET  /orgs/{id}/documents" -H "$AUTH" "$BASE/orgs/$ORG/documents"
code 200 "GET  /orgs/{id}/documents/{doc}" -H "$AUTH" "$BASE/orgs/$ORG/documents/$DOC"
code 200 "GET  /orgs/{id}/audit" -H "$AUTH" "$BASE/orgs/$ORG/audit"

# --- the boundaries ----------------------------------------------------------
code 401 "GET  /orgs/{id}/documents (no token)" "$BASE/orgs/$ORG/documents"

# An org id that exists for nobody. 404 rather than 403, and it is the same 404
# whether the org does not exist or the caller is not allowed to see it — the
# difference is information about other customers.
code 404 "GET  /orgs/{unknown}/documents" -H "$AUTH" \
  "$BASE/orgs/00000000-0000-4000-8000-000000000000/documents"

code 401 "GET  /auth/me with an API key" -H "authorization: Bearer wb_test_aaaaaaaa_secret" \
  "$BASE/auth/me"

echo
echo "smoke test passed"
