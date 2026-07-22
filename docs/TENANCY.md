# Tenancy

How one database serves many customers without anyone seeing anyone else's rows,
and why the enforcement lives in Postgres rather than in Python.

---

## The failure this design prevents

The common shape of a multi-tenant app:

```python
def get_documents(db, org_id):
    return db.query(Document).filter(Document.org_id == org_id).all()
```

This works. It works for two years. Then someone writes:

```python
def get_document(db, document_id):
    return db.query(Document).filter(Document.id == document_id).one()
```

because the caller said they already checked the org, and now `GET
/documents/{id}` returns another customer's document to anyone who can guess a
UUID. Or someone adds a report, a search endpoint, an admin export — and one of
them forgets the filter. The set of places that must not forget grows with the
codebase, and there is no test that can enumerate them.

Row-level security moves the filter into the database. The same buggy query now
returns nothing:

```sql
-- as the application role, inside a transaction that ran
--   SET LOCAL app.current_org = 'a1b2...'
SELECT * FROM documents WHERE id = 'someone-elses-uuid';
-- (0 rows)
```

The failure mode goes from *silent data leak* to *empty page*. Only one of those
is a phone call from your biggest customer.

---

## How it's wired

```
request
  │
  ├─ resolve the org: path param, X-Org header, or the `org` claim in the JWT
  ├─ verify the caller has a membership in it          ← application code
  │
  └─ open a transaction
       ├─ SET LOCAL app.current_org  = '<uuid>'        ← one line, once
       ├─ SET LOCAL app.current_user = '<uuid>'
       │
       ├─ every query in this transaction is filtered by RLS, automatically
       │
       └─ COMMIT — the settings evaporate with the transaction
```

The application sets the tenant once, and then stops thinking about it.

### `SET LOCAL`, not `SET`

This distinction is the whole ballgame under connection pooling.

| | Scope | Behaviour with a pool |
|---|---|---|
| `SET` | the session | survives the transaction; the next request that borrows the connection inherits the previous tenant |
| `SET LOCAL` | the transaction | reverted at commit or rollback |

With a pool of one and one user testing locally, both look identical. In
production, `SET` means request B occasionally reads as tenant A, under load,
non-deterministically. It is one of the least pleasant bugs in this business.

There's a test for it — `test_setting_is_scoped_to_the_transaction_and_leaks_nowhere`
— that opens a transaction, commits, then opens a *new* transaction on the same
pooled connection and asserts the setting is gone.

### `nullif(current_setting('app.current_org', true), '')::uuid`

Three pieces, each earning its place:

- `current_setting('x', true)` — the second argument means "return NULL instead
  of raising if the setting doesn't exist".
- `nullif(…, '')` — but it returns an *empty string* if something set it to an
  empty string, and `''::uuid` raises. That turns a misconfigured request into a
  500 instead of a denial. `nullif` makes it NULL, the comparison becomes NULL,
  and no rows match.
- `::uuid` — compares as a uuid, not as text. Text comparison happens to work
  until someone has a leading space.

### `ENABLE` vs `FORCE`

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;  -- policies apply to non-owners
ALTER TABLE documents FORCE  ROW LEVEL SECURITY;  -- ... and to the owner too
```

`ENABLE` alone is the trap. Policies do not apply to a table's owner unless
`FORCE` is set — so if your application connects as the role that owns the tables
(which is what happens by default when you have one database user), your policies
are decorative, your isolation tests pass if you run them as that role too, and
production is unprotected.

We set both, **and** we run the app as a role that owns nothing. Two independent
guarantees, because this is not a mistake you want a third chance at.

### `USING` vs `WITH CHECK`

| Clause | Applies to |
|---|---|
| `USING` | which rows a `SELECT`, `UPDATE` or `DELETE` can see |
| `WITH CHECK` | what a `INSERT`, or the *new* value of an `UPDATE`, is allowed to be |

A policy with only `USING` lets rows be read only by their tenant and *written
into any tenant*. That's the half people skip, and it's the half that lets a
missing filter in an insert path plant data in someone else's account — where it
waits, invisible to you, until they see it.

`scripts/check_rls.py` fails the build if a tenant table's insert path has no
`WITH CHECK`.

---

## Roles

Two database roles, and they are not interchangeable.

| Role | Owns tables | Runs migrations | Serves traffic | RLS applies |
|---|---|---|---|---|
| `workbench_admin` | yes | yes | no | no (owner) |
| `workbench` | no | no | yes | yes |

The application role:
- is `NOSUPERUSER` (superusers bypass RLS entirely)
- has no `BYPASSRLS`
- has no `CREATEDB`, no `CREATEROLE`
- holds `SELECT, INSERT, UPDATE, DELETE` on tables, and nothing else
- has `EXECUTE` on exactly one function, `auth_lookup_user`

That last one deserves a note. Login has to find a user by email before any
tenant is known — which means before `app.current_org` is set, which means the
`users` policy returns nothing. The options were:

1. Grant the app plain `SELECT` on `users`. Rejected: the users table then
   becomes a directory, readable from any query, and the RLS on it is pointless.
2. Connect as the owner for the login path. Rejected: a second connection pool
   with different security properties is a bug waiting for a busy Friday.
3. One `SECURITY DEFINER` function that returns a fixed set of columns for one
   email. **Chosen.**

`auth_lookup_user` returns nine columns for exactly one row, and is the only way
the application can see a user it doesn't already share an org with.

---

## Which tables are tenant-scoped

A table is tenant-scoped if it has an `org_id` column. That's the convention the
policy generator, the CI check, and the inspection helpers all key off — and it's
why `TenantScoped` in `core/models.py` hardcodes the column name rather than
letting each model choose.

| Table | Scoped | Policy |
|---|---|---|
| `organizations` | special | members read it; anyone with a user context can create one; only an owner can delete |
| `users` | no — org-adjacent | you see yourself and people who share an org with you |
| `memberships` | yes | `org_id = current_org` |
| `invitations` | yes | `org_id = current_org` |
| `documents` | yes | `org_id = current_org` |
| `api_keys` | yes | `org_id = current_org` |
| `audit_events` | yes | `org_id = current_org`, append-only |

`users` is the awkward one, and it's worth being explicit about why: a user is
not *owned* by an org. The policy therefore asks a different question — "do we
share a tenant" — rather than comparing to a single id. Ten lines of SQL instead
of a column that would be wrong for anyone in two orgs.

---

## Adding a tenant table

1. Add `org_id` via the `TenantScoped` mixin.
2. Add the table name to `TENANT_TABLES` in the migration that creates it.
3. Run `python scripts/check_rls.py`. It will tell you if you forgot.

Step 2 is the one that gets missed, which is why `check_rls` exists and why it's
a CI job rather than a line in a README that nobody reads.

The check asks four questions:

1. Does every table with `org_id` have **both** `ENABLE` and `FORCE`?
2. Does each of them have at least one policy?
3. Does each policy reference `current_setting`, rather than comparing to
   something that is always true? (A policy of `USING (true)` looks like
   protection and isn't.)
4. Does the application role own anything? If it does, RLS is optional for it.

---

## Testing

`tests/test_tenancy_isolation.py` holds a live connection open as the
application role and asserts on what Postgres returns:

- An unfiltered `SELECT *` returns exactly one org's rows.
- The other tenant's row cannot be fetched by primary key — proving it's
  *filtered*, not missing.
- An `INSERT` with the other org's id is rejected by the policy.
- An `UPDATE` that rewrites `org_id` is rejected.
- A `DELETE` removes only the current tenant's rows.

It runs as `workbench`, not `workbench_admin`, and that is the entire point. If
this suite ever starts connecting as the owner, every test passes and production
is different.

```bash
make up && make migrate && make test-db
```

`make test-db` also runs `check_rls`, so a migration that adds an unprotected
table can't merge even if nobody thinks to look.

---

## What this design costs

Being honest about the trade-offs:

- **Two database roles to manage.** One more thing to get right in every
  environment, and getting it wrong is silent.
- **Policies are hand-written SQL.** Alembic autogenerate can't produce them, so
  they're written by hand and reviewed by hand. `check_rls` catches the
  mechanical mistakes but not a policy that's logically wrong.
- **`SET LOCAL` per transaction.** One extra round-trip per request. On a local
  socket it's microseconds; over a slow link, batch it with the first query.
- **Debugging is confusing at first.** "This query returns nothing" with no
  error is disorienting until you remember the transaction has a tenant.
  `explain_policy()` in `core/db.py` exists for exactly that moment.
- **Analytics gets harder.** A warehouse query that spans all orgs needs a
  different role with `BYPASSRLS`, and that role must never be reachable from the
  application. Do it with a materialised view or a replica, not by loosening the
  app's grants.
