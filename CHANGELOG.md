# Changelog

## [0.1.0] — 2026-09-29

First release. The HTTP layer exists, every route has been run against a real
Postgres, and the trade-offs are written down where the code is.

The section at the bottom — *Found by running it* — is the part worth reading if
you are evaluating this. It is a list of ten defects that passed type checking,
passed lint, passed the unit suite, and were only visible once a request went
through the whole stack. Each one has a test now, and most of them are the kind
of bug that never reveals itself: silent, plausible, and in the direction of
"nothing happened".

### Added

**Tenancy**

- `organizations`, `memberships`, `invitations` — a user belongs to many orgs with
  a different role in each, joined through `memberships` rather than a `user.org_id`
  column, because the first consultant who needs access to two accounts would
  otherwise require a migration under load.
- Invitation tokens are stored **hashed**. They travel by email and land in inboxes;
  a database dump must not let anyone accept them.
- A partial unique index — `(org_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL`
  — allows exactly one *live* invitation per email while letting accepted and
  revoked rows accumulate as history.

**HTTP layer**

- 46 operations over 36 paths, all of them run: auth, organisations, members,
  invitations, API keys, the sample tenant resource, entitlements, billing,
  webhooks, a staff console, and health.
- RFC 7807 problem details everywhere, including for FastAPI's own validation
  errors — one parser for the client, not two shapes.
- `403` for a permission the role lacks, `402` for a limit the plan lacks, and
  the 402 body carries the plan code, the entitlement, the limit and the usage.
- Access tokens are org-bound and stateless; refresh tokens rotate and reuse is
  detected; the DB role beats any claim in the token.

**Row-level security** — the reason this repository exists

- `ENABLE` **and** `FORCE` on every tenant table. `FORCE` matters more and is the
  one people skip: without it, policies stop applying to the table's owner, which
  is precisely the role a single-database-user setup connects as.
- `USING` and `WITH CHECK` on every policy. A policy with only `USING` lets rows be
  read only by their tenant and *written into any tenant* — the half that lets a
  missing filter in an insert path plant data in someone else's account.
- Two database roles: `workbench_admin` owns the tables and runs migrations;
  `workbench` owns nothing and serves traffic. The separation removes the need to
  rely on `FORCE` alone.
- `auth_lookup_user()` as a `SECURITY DEFINER` function, because login has to find
  a user before any tenant is known. The alternative — granting the app `SELECT`
  on `users` — turns that table into a directory and makes its own RLS pointless.
- `nullif(current_setting('app.current_org', true), '')::uuid` rather than a bare
  cast. `current_setting(..., true)` returns an empty string when something set it
  to `''`, and `''::uuid` raises — turning a misconfigured request into a 500
  instead of a denial.
- `SET LOCAL` in the transaction, never `SET`. With a pool, `SET` leaks the tenant
  to whichever request borrows the connection next. There is a test.

**Permissions**

- One matrix: 16 permissions × 4 roles, all 64 cells asserted. Routes ask
  `can(role, "billing:write")`, never `role == "owner"`.
- Ranks are used only for "cannot outrank yourself". Equal ranks can't act on each
  other, which is what you want when two admins share an org.

**Auth**

- Argon2id at ~50ms; rehash on login when parameters change.
- Refresh tokens are a rotation chain, not a row. A used token presented again is
  *detectable* rather than merely invalid, so a replay revokes the family.
- API keys shaped `wb_live_<lookup>_<secret>`, with the secret hashed and the
  prefix in the clear for lookup. Scopes are intersected with the creator's own
  role — a member cannot mint a key with billing access.
- No composition rules on passwords. "One uppercase, one digit, one symbol"
  produces `Password1!` and nothing else.

**Billing**

- Plans are code, not rows: a pricing change is a pull request that lands
  identically in every environment.
- Entitlements are *resolved* from `(subscription, overrides, usage)` by a pure
  function — no database, no Stripe call, no clock — because this is the code
  whose bugs turn into refunds, so it should be the easiest code to test.
- Over-quota behaviour is per plan: free hard-stops, paid plans soft-warn and bill.
  Cutting off a paying customer mid-month is a refund conversation, not an upsell.
- Webhook idempotency by unique constraint on `stripe_events.event_id`, inserted
  *before* the work. The version that records afterwards sends the upgrade email
  twice.
- `past_due` keeps full access. A card that expired this morning should not take
  down a customer's integration; dunning exists to resolve it.
- Losing access is not all-or-nothing: reads keep working through a grace period
  so the customer can export before they go.

**Audit**

- Append-only enforced three ways: no ORM mutation path, no `UPDATE`/`DELETE`
  grant for the application role, and a trigger that blocks the owner too.
- `redact()` runs at the write, not at the call site, because the log is
  immutable — a secret written by accident cannot be removed afterwards.
- Staff actions require a reason. "Why did someone look at this account" is the
  only question that matters in an access review, and it can't be reconstructed later.

**Operations**

- `scripts/check_rls.py` — fails the build if a tenant table lacks `ENABLE`, lacks
  `FORCE`, has no policy, has a policy that doesn't reference the session setting,
  has an insert path with no `WITH CHECK`, or is owned by the application role.
- `Settings._validate_production()` refuses to boot if the app DSN equals the
  admin DSN — the single most dangerous misconfiguration in the system, and one
  that produces no symptom until it produces a breach.
- `scripts/seed.py` refuses to run outside development, and seeds an org at 94% of
  quota because the near-quota path is the state nobody tests.

**Tests** — 150+ unit tests, plus an isolation suite that runs as the application
role against a live Postgres.

### Not yet built

- HTTP routers and dependencies (`tenancy/router.py`, `auth/router.py`,
  `billing/router.py`, `admin/router.py`) — models, migrations and business rules
  are complete; the API surface is specified in SPEC.md §6.
- Stripe gateway implementation — the idempotency ledger and status machine exist;
  the API calls are stubbed.
- Celery tasks for email, usage rollup and dunning.
- Email templates.
- Webhook ordering tests (specified in SPEC.md FR-16).

---

### Found by running it

Ten things that were wrong, all of which passed every check that ran in CI, and
none of which produced an error message pointing at the actual cause. They are
listed here because the list is the most useful thing in this repository: each
one is a failure mode you will have too.

1. **Failed logins were not recorded.** The lockout counter and the
   `login_attempts` journal were written, then rolled back with the 401 that
   followed — the same transaction. `failed_login_count` stayed at zero forever,
   lockout never triggered, and a test asserting on status codes passed. Fixed
   by committing the evidence before raising: some writes are *about* the
   failure and have to outlive it.
2. **Refresh-token reuse detection revoked nothing.** Same cause, higher stakes:
   the family revocation ran, reported success to the log, and rolled back. There
   is now a `revoked == 0` guard that says so out loud.
3. **Creating an organisation failed with a row-level security violation.**
   Postgres applies the `SELECT` policies to the row an `INSERT … RETURNING`
   returns, and SQLAlchemy always returns. The new org satisfied the insert
   policy and not the read policy. The message pointed at the insert; the problem
   was the read.
4. **`GET /orgs` returned an empty list** for a user who owned three orgs. The
   policy on `organizations` says "an org you are a member of" with an `EXISTS`
   against `memberships` — which is itself tenant-scoped, so with no tenant set
   the subquery returned nothing. The policy read as correct and answered "no".
5. **Every API-key request failed.** A key resolves its identity through
   `Principal.actor_id`, which returned `None` for a key, so the membership check
   rejected a key whose owner was a member. The 403 said "you are not a member of
   this organisation", which is true of nobody in the flow.
6. **Roughly half of all issued API keys were unusable.** `token_urlsafe` emits
   `_`, and the parser split the key on `_` without a bound — so any secret
   containing a separator came back as six parts and failed the format check. A
   401 on a key minted thirty seconds earlier, on some keys and not others. A
   test now generates 500 keys and asserts every one round-trips.
7. **Accepted invitations were invisible.** There was no policy letting the
   acceptance path read an invitation by its token — the credential-shaped
   lookup every other token in the system has. The endpoint answered "invitation
   not found" for invitations that plainly existed, with nothing in the logs,
   because a policy that filters a row is not an error.
8. **Every audit event recorded a null actor.** `write_audit` inferred the actor
   from an `email` attribute; routes pass a principal object, which has none. The
   log read plausibly, which is why it survived. `org.created` was also written
   with a null `org_id` — the organisation *is* the org and has no `org_id`
   column — making the one event that proves the account existed invisible in
   that account's own log.
9. **Invoice events stopped changing anything.** The subscription id moved from
   `object.subscription` to `object.parent.subscription_details.subscription`,
   and the code read the old path. Payment failures folded as "no subscription
   id", logged at info, and moved nothing: no error, no alert, a customer whose
   card had been failing for a week.
10. **The state machine dropped its ordering clock.** `last_event_at` was written
    through `setattr` on the ORM object, which SQLAlchemy accepts for a name that
    is not a column and silently discards. It was also missing from the read path
    and from the write path. Every event was therefore compared against `None`
    and treated as the newest news, so a redelivered cancellation landed on top
    of an upgrade. There are columns for it now, and a check that raises when the
    state machine tries to write a field the table does not have.

Also fixed, found the same way:

- The rate limiter built a Redis client without connecting to it, so the startup
  log said `rate limiting: redis` while every limit failed open. It pings now,
  and one round trip at startup buys an honest line in the log.
- The rule "staff actions must carry a reason" was keyed on the *inferred* actor
  kind, so a support engineer signing into their own account — a `user.logged_in`
  event about nobody but themselves — raised and 500'd the login.
- The staff console wrote audit event names that were not in the closed set of
  known events, which raises by design. The fix was to add the four names, not to
  loosen the check: an event name that is not in the list is a filter on the
  review dashboard that never matches.
- The seed marked Acme's *owner* as staff and the account called `staff@` as not
  staff, so the demo could not reach the console and a customer's owner could.
- The seed was not idempotent: it generated fresh uuids on every run while
  `ON CONFLICT DO NOTHING` kept the first run's rows, so the second `make seed`
  failed on foreign keys.
- The staff console reported `requests_this_month: 0` for every customer, because
  the number was a stub — and the `?status=` filter it accepted was discarded on
  the floor. Both are real now; the seat count comes from a correlated subquery
  rather than a join, because a join to `usage_records` multiplies by meter and a
  console that reports the wrong seat count will be believed.
- `EmailStr` validates *deliverability*, which refuses the special-use TLDs —
  including `.test`, which exists for fixtures. Signup keeps that check, because
  we are about to send mail there; login now takes a plausible address, because
  re-validating deliverability at login means an account created before the rule
  changed can never be signed into again.
