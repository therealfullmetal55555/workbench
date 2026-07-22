# Walking the API by hand

Everything below is a real transcript against a real Postgres, seeded with
`make seed`. Nothing here is illustrative — it is what the API answers, with the
bodies trimmed where they run long.

The reason this file exists: the interesting properties of this project are
invisible in unit tests. "The wrong tenant gets a 403" and "the free plan gets a
402 with the numbers in it" are the whole product, and you want to see them
happen.

Start the app:

```bash
make seed && python3 -m workbench.cli serve --reload
```

---

### The plan catalogue, without a token

```
$ GET /plans
  → 200  [{"code":"free","name":"Free","description":"For trying it out. Three
          seats, a thousand requests, a week of history.","limits":{"seats":3,
          "monthly_requests":1000,"retention_days":7,"max_projects":1},
          "features":["audit_export","audit_log","data_residency"],
          "overage":"hard"}, {"code":"team", …}]
```

Public on purpose. The pricing page renders from the same catalogue the API
enforces, so a plan cannot be advertised with limits that are not the ones
applied. `enterprise` reports `"seats": null` — unlimited is not a large number.

---

### Signing in as a seeded owner

```
$ POST /auth/login  {"email": "owner@acme.test", "password": "correct-horse-battery-staple"}
  → 200  {"access_token": "eyJhbGciOiJIUzI1NiIs…", "refresh_token": "…",
          "expires_in": 900, "token_type": "bearer"}
```

The access token carries `org` — the organisation it acts on. A token that only
identified the user would let a browser keep sending a stale org after switching,
which is how a request for Acme's data returns Beta Co's.

```
$ GET /auth/me
  → 200  {"user": {"email": "owner@acme.test", "is_staff": false, …},
          "memberships": [{"org_slug": "acme", "org_name": "Acme Corporation",
                           "role": "owner", …}],
          "permissions": ["apikey:read", "apikey:write", "audit:read", …]}
```

One call, so the client renders its shell without N+1 requests to label an org
switcher.

---

### The tenant boundary

```
$ GET /orgs/{acme}/documents
  → 200  [{"id": "3eed6dd9-…", "title": "Acme internal document 3", …}]
```

That handler has no `WHERE org_id = …`. The session is bound to the tenant, the
policy filters, and the query cannot see another customer's rows even written
this way.

```
$ GET /orgs/{acme}/documents          (as member@beta.test)
  → 403  {"type": "https://workbench.dev/problems/forbidden",
          "title": "Permission denied",
          "detail": "you are not a member of this organisation",
          "instance": "/orgs/d1cb12c4-…/documents", "request_id": "44285e9f13984f64"}
```

---

### What the plan allows, and what happens when it doesn't

```
$ GET /orgs/{acme}/entitlements
  → 200  {"plan": {"code": "free", …},
          "limits":   {"seats": 3, "monthly_requests": 1000, "max_api_keys": 2,
                       "api_rate_limit_per_minute": 30},
          "usage":    {"seats": 2, "requests_this_month": 42000, …},
          "remaining":{"seats": 1, "requests_this_month": 0},
          "overage": "hard", "is_read_only": false}
```

`limits` is what the plan allows *for this org right now* — a plan override
applies, a trial applies, an enterprise contract applies, and this is the answer
after all of them. `usage` is counted from the rows rather than read from a
counter, because a counter drifts and it drifts in the customer's favour, which
is the direction nobody reports.

---

### The audit log

```
$ GET /orgs/{acme}/audit
  → 200  {"items": [{"event": "user.logged_in", "actor_kind": "user",
                     "actor_id": "810ca597-…", "actor_email": "owner@acme.test",
                     "target_label": "Ada Owner", "request_id": "…"}, …],
          "next_cursor": null}
```

Every row names who did it — which sounds like the minimum for an audit log and
was, briefly, not true: the first version recorded every route-level event with a
null actor, because it looked for an `email` attribute on what is actually a
principal object. It read plausibly, which is why it took a query against the
table to notice.

---

### The staff console

```
$ GET /staff/orgs          (as owner@acme.test — a customer, not staff)
  → 403  {"type": "https://workbench.dev/problems/forbidden",
          "detail": "staff access required"}

$ GET /staff/orgs          (as staff@workbench.test)
  → 200  [{"slug": "beta-co", "plan_code": "free", "status": "none", "seats": 1,
           "requests_this_month": 940, …},
          {"slug": "acme", "plan_code": "free", "seats": 2,
           "requests_this_month": 42000, …}]
```

Staff is `User.is_staff` and never an org role: someone who can read across
customers is not an owner of anything. The console reads through per-table
`*_staff_read` policies, with no `BYPASSRLS` role anywhere in the system.

```
$ GET /staff/orgs/{acme}
  → 200  {"org": {…}, "members": [{…}], "subscription": null,
          "login_history": [{"succeeded": true, "ip_address": "127.0.0.1"}, …],
          "impersonations": []}
```

Opening this page writes `staff.org_viewed` into **Acme's** audit log — the
tenant is bound before the event is written, because a record the customer can't
see isn't notice. Support looking at an account is legitimate; a pattern of
looking at one account is what the log is for.

---

### Operational endpoints

```
$ GET /webhooks/stripe/health
  → 200  {"pending": 0, "with_errors": 0, "healthy": true}

$ GET /health/ready
  → 200  {"status": "ok", "checks": {"database": "ok"}}

$ GET /health/live
  → 200  {"status": "ok"}
```

`live` never touches the database: a probe that checks a dependency restarts
every replica when the dependency hiccups, turning a ten-second blip into a
fleet-wide cold start. `ready` does check it, and returns 503 when it can't.

---

## Reproducing the two properties worth reproducing

**The wrong tenant is invisible, at the database level.** Run the same
`SELECT *` as the application role under two tenants:

```bash
make check-rls     # 11 tenant tables, 47 policies, and the one documented exemption
pytest -m database -k isolation -v
```

**A free org cannot get a fourth seat.** The suite does it through the API:

```bash
pytest tests/test_api.py -k "fourth_seat" -v
```

And the subscription state machine is exercised against every delivery order
Stripe can produce — the case that matters is an upgrade where the *new*
subscription arrives before the cancellation of the old one:

```bash
pytest tests/test_billing_state_machine.py -v
```
