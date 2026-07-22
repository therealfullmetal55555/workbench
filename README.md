# workbench

A multi-tenant SaaS foundation: organisations, roles, invitations, billing,
entitlements, audit log, admin console. FastAPI + PostgreSQL with row-level
security, Stripe for money, Celery for the slow parts.

Everything in here exists because a specific thing went wrong in production.
Those reasons are written down next to the code, not in a blog post.

```
make up && make migrate && make seed
open http://localhost:8000/docs
```

---

## The problem this solves

Every multi-tenant product rebuilds the same six things, and gets three of them
subtly wrong:

| Thing | Where people go wrong |
|---|---|
| Tenant isolation | Filtering by `org_id` in application code, at every query, forever |
| Roles | A boolean `is_admin` that eventually needs a fourth value |
| Invitations | A link that works after the invitee is removed from the org |
| Billing | Webhooks applied twice, entitlements computed from Stripe on every request |
| Usage limits | Checked in the UI only, so the API is unbounded |
| Audit log | A `updated_at` column, and no idea who did it |

`workbench` is those six things, done once, with the failure each design choice
prevents written down beside it.

---

## The one design decision that matters

**Isolation is enforced by Postgres, not by your application code.**

```sql
CREATE POLICY tenant_isolation ON documents
  USING (org_id = current_setting('app.current_org', true)::uuid);
```

The application sets `app.current_org` once per request, inside the transaction.
After that, a query that forgets its `WHERE org_id = ...` returns nothing instead
of returning another customer's data. The failure mode changes from *silent data
leak* to *empty page*, and only one of those is a phone call.

There is a test that proves it — it connects as the application role, sets one
tenant, and asserts that a `SELECT *` with no filter comes back with exactly one
org's rows. That test is the reason this repo exists.

Full explanation, including why `FORCE ROW LEVEL SECURITY` is on every table and
what that costs: [docs/TENANCY.md](docs/TENANCY.md).

---

## Specification matrix

| Dimension | This project |
|---|---|
| **Purpose** | SaaS foundation — tenancy, auth, roles, billing, entitlements, audit |
| **Stack** | Python 3.11 · FastAPI · SQLAlchemy 2.0 async · PostgreSQL 16 · Redis 7 · Celery · Stripe |
| **Isolation** | PostgreSQL row-level security, `FORCE`-enabled, one policy per tenant table |
| **Auth** | Argon2id passwords · JWT access (15 min) · rotating refresh (30 d, reuse-detected) · hashed API keys |
| **Authorisation** | 4 roles × 16 permissions, resolved through one function, tested exhaustively |
| **Billing** | Stripe Checkout + Billing Portal · idempotent webhooks · plan catalogue in code · usage metering |
| **Entitlements** | Plan → limits → `check()`; per-org overrides for sales deals, all audited |
| **Audit** | Append-only table, `UPDATE`/`DELETE` revoked at the database level |
| **Admin** | Staff-only org search, plan override, impersonation (logged, time-boxed, no writes) |
| **Interfaces** | 46 REST operations over 36 paths · OpenAPI at `/docs` · Stripe webhooks · Celery workers · CLI |
| **Tests** | 232 tests: isolation, permissions, entitlements, the billing state machine under every delivery order, webhook signature and replay, refresh rotation, lockout, audit immutability |
| **Ops** | Docker Compose · Alembic · health/readiness · structured logs · OpenTelemetry hooks |
| **Licence** | MIT |

---

## Tenancy

```
User ──< Membership >── Organization ──< Invitation
                              │
                              ├──< Subscription ──> Plan (code, not DB)
                              ├──< UsageRecord
                              └──< AuditEvent
```

- A user can belong to many orgs, with a different role in each.
- The **active org** comes from the request (header, path, or JWT claim) and is
  validated against the caller's memberships *before* anything else happens.
- Switching orgs re-issues the access token. There's no "switch and hope" — the
  token carries the org it was minted for.

Roles:

| Role | Read | Write | Invite | Manage billing | Delete org | Transfer ownership |
|---|---|---|---|---|---|---|
| `owner` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `admin` | ✓ | ✓ | ✓ | ✓ | — | — |
| `member` | ✓ | ✓ | — | — | — | — |
| `viewer` | ✓ | — | — | — | — | — |

The matrix lives in one dict, `PERMISSIONS`, and every route asks
`can(role, "billing:write")`. Adding a role is one entry, not a grep for
`is_admin` across forty files.

---

## Billing and entitlements

**Plans are code, not rows.** The catalogue is versioned in git, reviewable in a
PR, and identical across environments. Stripe holds the price ids; the plan
defines the limits.

```python
PLANS = {
    "free":       Plan(seats=3,   monthly_requests=1_000,    retention_days=7,   sso=False),
    "team":       Plan(seats=25,  monthly_requests=100_000,  retention_days=90,  sso=False),
    "enterprise": Plan(seats=None, monthly_requests=None,    retention_days=730, sso=True),
}
```

**Entitlements are resolved, never inferred.**

```python
ent = await entitlements.for_org(org_id)
if not ent.allows("sso"):
    raise HTTPException(402, "SSO is available on Enterprise")
```

Resolution order: active subscription → plan → per-org overrides → defaults. The
whole thing is a pure function over three inputs, which is why it's the most
heavily tested module in the repo.

**Webhooks are idempotent by construction.** Every event is inserted into
`stripe_events` with a unique constraint on `stripe_event_id` *before* it's
processed. Stripe retries; the second attempt hits the constraint and becomes a
no-op. This is the difference between one upgrade email and four.

**Usage is metered at the edge, checked inside the transaction.** A counter in
Redis absorbs the read load, and the authoritative row is incremented in the same
transaction as the work it pays for. Over-quota behaviour is per plan: `free`
hard-stops, paid plans soft-warn and bill overage, because cutting off a paying
customer mid-month is a refund conversation, not an upsell.

---

## Auth

- Argon2id, via `argon2-cffi` defaults. Not bcrypt, not a hand-rolled loop.
- Access tokens: JWT, 15 minutes, carry `sub`, `org`, `role`, `jti`.
- Refresh tokens: opaque, 30 days, stored hashed, **rotated on every use**. A
  reused refresh token means the token leaked — the family is revoked and the
  event is audited.
- API keys: `wb_live_<prefix>_<secret>`, the secret hashed at rest, prefix stored
  in the clear for lookup. Same shape as Stripe's, for the same reason.

---

## Audit log

Every state change that a customer might ask about goes through `write_audit()`
inside the same transaction as the change. If the write fails, the change rolls
back.

The table has no `UPDATE` or `DELETE` grant for the application role, and there's
a CI check that fails if a migration ever adds one. An audit log you can edit is
a log nobody trusts.

```
event          org_id  actor         target              before → after
billing.plan   acme    user_8f21     subscription_1192   team → enterprise
member.role    acme    user_8f21     user_31ab           member → admin
```

---

## Admin console

For staff, behind a separate `is_staff` flag that is **not** part of the org role
system — conflating "works here" with "admin of this customer" is how you end up
with a support agent who can't be removed from a customer's org.

- Search orgs by name, domain, plan, or Stripe customer id.
- Override a plan or a limit, with a mandatory reason (it lands in the audit log).
- Impersonate a user: read-only, time-boxed to 60 minutes, banner-noted in the
  response headers, and audited on start and end.

---

## Quickstart

```bash
git clone https://github.com/therealfullmetal55555/workbench.git
cd workbench
cp .env.example .env
make up            # postgres, redis, mailhog, api, worker
make migrate
make seed          # two orgs, four users, one near its quota, one staff account
open http://localhost:8000/docs
```

Seeded logins (dev only — `make seed` refuses to run when `ENVIRONMENT=production`):

| Email | Password | Org | Role |
|---|---|---|---|
| `owner@acme.test` | `correct-horse-battery-staple` | Acme | owner |
| `admin@acme.test` | `correct-horse-battery-staple` | Acme | admin |
| `member@beta.test` | `correct-horse-battery-staple` | Beta Co | member |
| `staff@workbench.test` | `correct-horse-battery-staple` | — | staff |

Beta Co is seeded at 94% of its free-tier request quota, deliberately: the
near-quota path is the one nobody exercises until a customer is in it. And the
staff flag belongs to exactly one account, which belongs to no organisation —
support access to the console and membership of a customer's org are different
things, and a fixture that merges them teaches the wrong shape.

`make seed` is idempotent. Running it twice is a no-op rather than a foreign key
violation on the ids from the first run.

There is a walkthrough of the API with real request and response bodies, seeded
data included, in [docs/DEMO.md](docs/DEMO.md).

---

## Commands

```bash
make help            # every target
make up down logs    # docker compose
make migrate         # alembic upgrade head
make revision m="..."  # new migration, autogenerated
make seed            # dev fixtures
make test            # unit tests, no database needed
make test-db         # database + HTTP suites (needs postgres — this is the important one)
make test-all        # everything, including the two above
make lint fmt type   # ruff, black, mypy
make check-rls       # fails if a tenant table has no policy
make smoke           # end-to-end walk through a running API (also the CI job)
make package         # dist/workbench-<version>.tar.gz
make stripe-listen   # forward webhooks to the local API
python3 -m workbench.cli plans     # the catalogue, from the code that enforces it
python3 -m workbench.cli matrix    # the role x permission table
```

The CLI is also where `check-rls` and `grant-staff` live; `grant-staff` refuses
to run outside development without `--yes`, because giving somebody the ability
to read every customer's data is not something to do by accident.

---

## What's deliberately missing

- **No SSO/SAML implementation.** The entitlement is modelled and gated; the
  actual integration is per-customer work with a per-customer metadata shape.
- **No frontend.** This is the API and the console endpoints; a UI belongs in its
  own repo with its own release cadence.
- **No Kubernetes manifests.** Compose for local, and a documented path to
  whatever you already run. Inventing a cluster config here would be fiction.
- **No background job dashboard.** Celery's own Flower is fine.
- **No email templates for your product.** Five are here (invitation, password
  reset, payment failure, dunning, export ready) and they are the five the
  boilerplate itself sends. Yours go beside them.
- **No staff console UI.** The endpoints, the reason requirement and the audit
  trail are implemented; the page that calls them belongs in the frontend.

---

## Licence

MIT — see [LICENSE](LICENSE).
