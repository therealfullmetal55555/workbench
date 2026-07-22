# Specification

Maintainer's reference. The README is for people deciding whether to use this;
this is for people who already do.

---

## 1. Scope

**In scope** — organisations and memberships, roles and permissions, invitations,
authentication and API keys, plans and entitlements, Stripe billing with
idempotent webhooks, usage metering, an append-only audit log, and a staff
console.

**Out of scope** — SSO/SAML implementation (modelled and gated, not built), a
frontend, Kubernetes manifests, an LLM or AI feature of any kind, and anything
requiring a message broker beyond Redis.

---

## 2. Functional requirements

| ID | Requirement | Verified by |
|---|---|---|
| FR-1 | A user may belong to many orgs with a different role in each | `uq_memberships_user_id_org_id`, `test_tenancy_isolation.py` |
| FR-2 | Tenant isolation is enforced by the database, not application filters | `test_unfiltered_select_returns_one_tenant_only` |
| FR-3 | Cross-tenant writes are refused, not just cross-tenant reads | `test_writes_cannot_land_in_another_tenant` |
| FR-4 | `org_id` cannot be rewritten by an update | `test_reassigning_org_id_is_blocked` |
| FR-5 | Tenant context does not survive the transaction | `test_setting_is_scoped_to_the_transaction_and_leaks_nowhere` |
| FR-6 | A missing tenant context denies access, never falls back to all rows | `test_bypass_requires_saying_so_out_loud` |
| FR-7 | Every permission decision goes through one matrix | `test_permissions.py`, all 64 cells |
| FR-8 | Nobody can assign a role at or above their own | `test_nobody_can_promote_to_their_own_level` |
| FR-9 | Staff status is orthogonal to org roles | `User.is_staff` vs `Membership.role`, `test_admin.py` |
| FR-10 | Invitations are single-use and email-bound | `Invitation.accept`, `uq_invitations_pending_email` |
| FR-11 | Refresh tokens rotate, and reuse is detectable | `RefreshToken.looks_like_reuse` |
| FR-12 | Plans are code; limits resolve from plan + overrides + usage | `test_entitlements.py` |
| FR-13 | Unknown plan codes resolve to the most restrictive plan | `test_unknown_plan_code_falls_back_to_free_not_unlimited` |
| FR-14 | Free plans hard-stop; paid plans soft-warn and bill overage | `test_paid_plan_soft_overage_passes_through` |
| FR-15 | Webhooks are idempotent by unique constraint, not by a check | `stripe_events.event_id`, `test_billing.py` |
| FR-16 | Webhook handling is order-independent | `test_billing.py::test_out_of_order_delivery` |
| FR-17 | The audit log cannot be updated or deleted, by anyone | trigger + grants, `test_audit_immutability` |
| FR-18 | Secrets cannot reach the audit log | `redact()`, `test_audit.py` |
| FR-19 | Usage is counted in the transaction that did the work | `UsageRecord`, `test_usage.py` |
| FR-20 | Staff overrides require a reason and are audited | `write_audit(actor_kind="staff")` |

---

## 3. Non-functional requirements

| ID | Requirement | Target | Verified by |
|---|---|---|---|
| NFR-1 | Tenant overhead per request | one extra round-trip | `SET LOCAL` in `set_tenant` |
| NFR-2 | Statement timeout | 15s, per transaction | `_apply_statement_timeout` |
| NFR-3 | Password hashing cost | ~50ms (argon2id, 64 MiB, t=2) | `passwords.py` |
| NFR-4 | Access token lifetime | 15 minutes | `ACCESS_TOKEN_MINUTES` |
| NFR-5 | A leaked database alone is not enough to authenticate | argon2 for passwords, peppered SHA-256 for tokens | `hash_token` |
| NFR-6 | PII never lands in the audit log | `redact()` applied at write | `test_audit.py` |
| NFR-7 | Every tenant table is protected, always | CI job `check_rls` | `scripts/check_rls.py` |
| NFR-8 | Unit suite runs in under a second | no I/O in `-m unit` | `make test` |
| NFR-9 | A migration that adds an unprotected table cannot merge | `check_rls` fails the build | `.github/workflows/ci.yml` |

---

## 4. Data model

```
users ──< memberships >── organizations ──< invitations
  │                            │
  │                            ├── subscription (1:1)
  │                            ├──< usage_records
  │                            ├──< plan_overrides
  │                            └──< audit_events
  ├──< refresh_tokens
  ├──< api_keys
  ├──< password_resets
  ├──< login_attempts
  └──< staff_impersonations
```

| Table | Tenant-scoped | RLS | Immutable |
|---|---|---|---|
| `organizations` | itself | 4 policies (select/insert/update/delete) | no |
| `users` | no | self-or-co-member | no |
| `memberships` | yes | `tenant_isolation` | no |
| `invitations` | yes | `tenant_isolation` | no |
| `documents` | yes | `tenant_isolation` | no |
| `api_keys` | yes | `tenant_isolation` | no |
| `subscriptions` | yes | `tenant_isolation` | no |
| `usage_records` | yes | `tenant_isolation` | no |
| `plan_overrides` | yes | `tenant_isolation` | no |
| `stripe_events` | global | none — staff/system only | effectively |
| `audit_events` | yes (nullable org) | `tenant_isolation` | **append-only** |

`stripe_events` has no RLS because it is not tenant data — it is the ledger of
what Stripe told us, and the application role touches it only from the webhook
path, which runs with `bypass=True` and is audited.

---

## 5. Permission matrix

16 permissions × 4 roles. See `src/workbench/core/permissions.py` and
`make plans` for the generated version.

| Permission | owner | admin | member | viewer |
|---|---|---|---|---|
| org:read | ✓ | ✓ | ✓ | ✓ |
| org:update | ✓ | ✓ | | |
| org:delete | ✓ | | | |
| org:transfer | ✓ | | | |
| member:read | ✓ | ✓ | ✓ | ✓ |
| member:invite | ✓ | ✓ | | |
| member:update_role | ✓ | ✓ | | |
| member:remove | ✓ | ✓ | | |
| billing:read | ✓ | ✓ | ✓ | ✓ |
| billing:write | ✓ | ✓ | | |
| apikey:read | ✓ | ✓ | ✓ | |
| apikey:write | ✓ | ✓ | | |
| audit:read | ✓ | ✓ | | |
| data:read | ✓ | ✓ | ✓ | ✓ |
| data:write | ✓ | ✓ | ✓ | |
| data:delete | ✓ | ✓ | | |

Rank is used only for "cannot outrank yourself" — never for permission checks.

---

## 6. API surface

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/auth/signup` | — | Creates a user; no org |
| POST | `/auth/login` | — | Returns access + refresh; carries the active org |
| POST | `/auth/refresh` | — | Rotates; reuse revokes the family |
| POST | `/auth/logout` | — | Revokes the presented refresh token |
| GET | `/auth/me` | — | Caller plus their memberships |
| POST | `/orgs` | — | Creator becomes owner |
| GET | `/orgs` | — | Orgs the caller belongs to |
| GET | `/orgs/{org}/entitlements` | org:read | Feeds the billing screen |
| PATCH | `/orgs/{org}` | org:update | |
| DELETE | `/orgs/{org}` | org:delete | Soft by default; `?hard=true` for real |
| POST | `/orgs/{org}/transfer` | org:transfer | Requires the target to be an admin |
| GET | `/orgs/{org}/members` | member:read | |
| POST | `/orgs/{org}/invitations` | member:invite | Seat limit enforced here |
| POST | `/invitations/{token}/accept` | — | Email must match |
| PATCH | `/orgs/{org}/members/{user}` | member:update_role | Rank-checked |
| DELETE | `/orgs/{org}/members/{user}` | member:remove | Last owner cannot be removed |
| GET | `/orgs/{org}/audit` | audit:read | Cursor paginated |
| POST | `/orgs/{org}/api-keys` | apikey:write | Scopes ∩ role permissions |
| POST | `/billing/checkout` | billing:write | Stripe Checkout session |
| POST | `/billing/portal` | billing:write | Stripe Billing Portal |
| POST | `/webhooks/stripe` | — | Signature verified; idempotent |
| GET | `/staff/orgs` | staff | Search |
| POST | `/staff/orgs/{org}/override` | staff | Reason mandatory |
| POST | `/staff/impersonate` | staff | Read-only, ≤60 min, audited |

Errors are RFC 7807 problem details, so a 402 carries the limit and the plan:

```json
{
  "type": "https://workbench.dev/problems/quota-exceeded",
  "title": "Seat limit reached",
  "status": 402,
  "detail": "seats limit reached on the free plan (3/3)",
  "plan": "free",
  "entitlement": "seats",
  "limit": 3,
  "used": 3
}
```

Status code choices: `403` for a permission the role doesn't hold, `402` for a
limit the plan doesn't include. They are different conversations with the
customer and they should not look the same.

---

## 7. Security

| Concern | Approach |
|---|---|
| Password storage | argon2id, t=2, 64 MiB, p=1; rehash on login when parameters change |
| Token storage | SHA-256 over a 48-byte app pepper; tokens are 256-bit so a KDF buys nothing |
| Refresh tokens | Opaque, hashed, 30d, rotated on use, family revoked on reuse |
| API keys | `wb_live_<lookup>_<secret>`; secret hashed, prefix plain for lookup |
| Session fixation | Access token binds the org it was minted for; switching re-issues |
| Rate limiting | Per-IP on auth (`20/min`), per-key on the API (`plan.api_rate_limit_per_minute`) |
| Enumeration | Signup and password reset return the same response either way |
| Timing | Argon2 verify on a dummy hash when the user doesn't exist |
| PII in logs | `redact()` on every audit write; no request bodies logged |
| SQL injection | Parameterised everywhere; `SET LOCAL` uses `set_config`, not interpolation |
| Privilege escalation | Staff flags are separate from org roles and require a reason to use |

---

## 8. Failure modes

| Failure | Detection | Behaviour | Recovery |
|---|---|---|---|
| Postgres unreachable | `/health/ready` returns 503 | load balancer drains the instance | failover |
| RLS accidentally disabled | `check_rls` in CI; `verify_rls_active` at startup | **refuse to start** | fix the migration |
| `SET LOCAL` replaced with `SET` | isolation suite | tests fail | revert |
| App connected as the owner | `check_rls`; identical-DSN check in settings | **refuse to boot in production** | fix the DSN |
| Stripe webhook duplicated | unique constraint | second delivery is a no-op, 200 | none needed |
| Stripe webhook out of order | order-independent handlers | final state matches Stripe | none needed |
| Stripe unreachable | `stripe_events.last_error`, attempts | retry with backoff; alert after 5 | manual replay |
| Cache down | Redis ping in readiness | degrade to database reads, don't fail | Redis restart |
| Clock skew | tokens validated with 30s leeway | small skew tolerated | NTP |
| Migration adds an unprotected table | `check_rls` | build fails | add the table to `TENANT_TABLES` |

The second row is the one to understand. Every other failure is an outage. That
one is a breach, so the application refuses to start rather than run without
isolation.

---

## 9. Configuration

| Variable | Required in prod | Notes |
|---|---|---|
| `DATABASE_DSN` | yes | Must **not** be the owner role; validated against `DATABASE_ADMIN_DSN` |
| `DATABASE_ADMIN_DSN` | yes | Migrations only |
| `REDIS_DSN` | yes | |
| `JWT_SECRET` | yes | ≥32 chars; also the token-hash pepper — rotating it invalidates every token |
| `STRIPE_SECRET_KEY` | if billing | |
| `STRIPE_WEBHOOK_SECRET` | if billing | Refuses to start without it |
| `STRIPE_PRICE_IDS` | if billing | JSON map of plan code → price id |
| `ENVIRONMENT` | yes | Anything but `production` relaxes the startup checks |

`Settings._validate_production()` refuses to boot if debug is on, DSNs point at
localhost, the JWT secret is short, billing is enabled without Stripe keys, or
the two DSNs are identical.

---

## 10. Extension points

**A new permission** — add to the `Permission` literal, the `MATRIX`, and the
expected dict in `test_permissions.py`. The test fails until you do, which is the
reminder to decide who gets it.

**A new tenant table** — mix in `TenantScoped`, add the table name to
`TENANT_TABLES` in the migration, run `make check-rls`.

**A new plan** — one entry in `CATALOGUE`, one price id in `STRIPE_PRICE_IDS`,
one migration only if the plan needs storage beyond the catalogue.

**A new webhook event** — add the handler, register it, and make it fetch current
state rather than applying a delta. Never assume it arrives once, or in order.

**A new audit event** — add it to `EVENT_KINDS`. The writer raises on unknown
names, so a typo is caught at the first occurrence rather than producing a filter
that never matches.
