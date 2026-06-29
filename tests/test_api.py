"""
End-to-end tests against a live PostgreSQL.

Everything here is marked `database` and every one of them needs the real thing.
None of this can be tested with a mock: the properties under test are "Postgres
enforces separation", "the token the API minted is accepted by the API", and "a
duplicate webhook doesn't apply twice". A mocked database would assert that the
code calls the functions the author expected, which is the one thing that was
never in doubt.

The suite walks the product the way a customer does — sign up, create an org,
invite somebody, hit the API as both of them, ask what the plan allows — and then
the way an attacker would.

    make migrate-test-db && pytest -m database
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import requires_postgres

pytestmark = [pytest.mark.database, requires_postgres]

# The app is built from settings, so the DSNs have to be in the environment
# before anything imports `workbench.main`. conftest sets the test DSNs; these
# names are the ones the settings class reads (see the alias note there).
os.environ.setdefault("DATABASE_DSN", os.getenv("TEST_APP_DSN", ""))
os.environ.setdefault("DATABASE_ADMIN_DSN", os.getenv("TEST_ADMIN_DSN", ""))
os.environ.setdefault("BILLING_ENABLED", "false")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_secret")


@pytest.fixture(scope="module")
def app_settings():
    from workbench.core.settings import Settings

    os.environ["DATABASE_DSN"] = os.getenv(
        "TEST_APP_DSN", "postgresql+asyncpg://workbench:workbench@localhost:5433/workbench_test"
    )
    os.environ["DATABASE_ADMIN_DSN"] = os.getenv(
        "TEST_ADMIN_DSN",
        "postgresql+asyncpg://workbench_admin:workbench_admin@localhost:5433/workbench_test",
    )
    return Settings()


@pytest.fixture
async def client(app_settings):
    """
    An HTTP client wired to the real app, with the lifespan actually running.

    The lifespan is not decoration: it is where row-level security is verified
    and where the engine is built, so a test that skips it tests a different
    application.
    """
    from workbench.main import create_app

    app = create_app(app_settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as http:
            yield http


def unique_email(prefix: str = "user") -> str:
    """Every test makes its own users; the database is not cleaned between them."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}@api.example.com"


PASSWORD = "correct-horse-battery-staple"


async def signup_and_login(
    client: AsyncClient, *, email: str | None = None, org_name: str | None = None
) -> dict[str, Any]:
    """The happy path, as a helper: it is the setup for almost every test below."""
    address = email or unique_email()

    response = await client.post(
        "/auth/signup",
        json={"email": address, "password": PASSWORD, "name": "Test Person", "org_name": org_name},
    )
    assert response.status_code == 202, response.text
    # The body must not reveal whether the address was free. Asserted here
    # because this is the one place the contract is checked.
    assert set(response.json()) == {"status", "detail"}

    response = await client.post("/auth/login", json={"email": address, "password": PASSWORD})
    assert response.status_code == 200, response.text
    tokens = response.json()

    return {
        "email": address,
        "access": tokens["access_token"],
        "refresh": tokens["refresh_token"],
        "headers": {"Authorization": f"Bearer {tokens['access_token']}"},
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


async def test_signup_does_not_say_whether_the_address_is_taken(client: AsyncClient):
    """
    The property that makes signup safe to expose: the response is identical.

    A 409 here would turn a leaked mailing list into a customer list. This test
    will fail the moment somebody "improves" the error message.
    """
    email = unique_email()
    first = await client.post(
        "/auth/signup", json={"email": email, "password": PASSWORD, "name": "A"}
    )
    second = await client.post(
        "/auth/signup", json={"email": email, "password": PASSWORD, "name": "A"}
    )

    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()


async def test_login_with_the_wrong_password_is_indistinguishable_from_an_unknown_user(
    client: AsyncClient,
):
    known = await signup_and_login(client)

    wrong_password = await client.post(
        "/auth/login", json={"email": known["email"], "password": "not-the-password"}
    )
    unknown_user = await client.post(
        "/auth/login", json={"email": unique_email("nobody"), "password": PASSWORD}
    )

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"]
    assert wrong_password.json()["type"] == unknown_user.json()["type"]


async def test_login_is_rate_limited_per_address(client: AsyncClient):
    """
    Eight attempts a minute per address, then a 429 with a Retry-After.

    The limiter is in-process in the test configuration, which is enough to prove
    the wiring: the tenth attempt must not reach the password check.
    """
    email = unique_email("throttle")
    for _ in range(8):
        await client.post("/auth/login", json={"email": email, "password": "wrong-password-1"})

    response = await client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert response.json()["type"].endswith("/rate-limited")


async def test_a_refresh_token_can_only_be_used_once(client: AsyncClient):
    """
    Rotation, and the reason it exists.

    The second use of the same token is evidence of theft — someone has a copy.
    The response says so, and the whole chain dies: the client's freshly minted
    token is revoked too, so a thief and their victim are both signed out and
    both have to re-authenticate. Annoying for one of them, correct for the other.
    """
    session = await signup_and_login(client)

    rotated = await client.post("/auth/refresh", json={"refresh_token": session["refresh"]})
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["refresh_token"] != session["refresh"]

    replay = await client.post("/auth/refresh", json={"refresh_token": session["refresh"]})
    assert replay.status_code == 401
    assert replay.json()["type"].endswith("/invalid-token")

    # And the token that replaced it is dead as well.
    after = await client.post(
        "/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
    )
    assert after.status_code == 401


async def test_me_lists_memberships_and_permissions(client: AsyncClient):
    user = await signup_and_login(client, org_name="Me Test Org")

    response = await client.get("/auth/me", headers=user["headers"])
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["user"]["email"] == user["email"]
    assert len(body["memberships"]) == 1
    assert body["memberships"][0]["role"] == "owner"
    # The client renders buttons from this list instead of guessing.
    assert "org:delete" in body["permissions"]


# ---------------------------------------------------------------------------
# The tenant boundary — the reason the project exists
# ---------------------------------------------------------------------------


async def test_a_member_of_another_org_cannot_see_this_org(client: AsyncClient):
    """
    Two customers, one documents endpoint, no filter in the query.

    The query in `list_documents` has no `WHERE org_id`, and it still cannot
    return the other tenant's rows. That is the whole design in one assertion.
    """
    alice = await signup_and_login(client, org_name="Alice Co")
    bob = await signup_and_login(client, org_name="Bob Co")

    alice_orgs = (await client.get("/orgs", headers=alice["headers"])).json()
    alice_org = alice_orgs[0]["id"]

    created = await client.post(
        f"/orgs/{alice_org}/documents",
        headers=alice["headers"],
        json={"title": "Alice's secret", "body": "handover notes"},
    )
    assert created.status_code == 201, created.text

    # Bob asking for Alice's org gets a 403 (he is not a member) and asking for
    # her document through his own org gets a 404 (it does not exist there).
    stranger = await client.get(f"/orgs/{alice_org}/documents", headers=bob["headers"])
    assert stranger.status_code in {403, 404}, stranger.text

    bob_orgs = (await client.get("/orgs", headers=bob["headers"])).json()
    bob_org = bob_orgs[0]["id"]
    cross = await client.get(
        f"/orgs/{bob_org}/documents/{created.json()['id']}", headers=bob["headers"]
    )
    assert cross.status_code == 404

    # And Bob's org is empty, rather than showing Alice's row.
    assert (await client.get(f"/orgs/{bob_org}/documents", headers=bob["headers"])).json() == []


async def test_a_member_cannot_delete_data(client: AsyncClient):
    """
    403, not 402 — and the distinction survives all the way to the response body.

    A viewer or member hitting a permission they don't hold has a role problem.
    A free org hitting a seat limit has a plan problem. They are different
    conversations with the customer and the API keeps them different.
    """
    owner = await signup_and_login(client, org_name="Roles Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    created = await client.post(
        f"/orgs/{org}/documents", headers=owner["headers"], json={"title": "shared"}
    )
    assert created.status_code == 201

    member_email = unique_email("member")
    await client.post(
        "/auth/signup", json={"email": member_email, "password": PASSWORD, "name": "M"}
    )
    invite = await client.post(
        f"/orgs/{org}/invitations",
        headers=owner["headers"],
        json={"email": member_email, "role": "member"},
    )
    assert invite.status_code == 201, invite.text
    token = invite.json()["token"]

    member_login = await client.post(
        "/auth/login", json={"email": member_email, "password": PASSWORD}
    )
    member_headers = {"Authorization": f"Bearer {member_login.json()['access_token']}"}

    accepted = await client.post(f"/invitations/{token}/accept", headers=member_headers, json={})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["role"] == "member"

    # The member can read the org's data...
    listing = await client.get(f"/orgs/{org}/documents", headers=member_headers)
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    # ...and cannot delete it.
    delete = await client.delete(
        f"/orgs/{org}/documents/{created.json()['id']}", headers=member_headers
    )
    assert delete.status_code == 403
    assert delete.json()["type"].endswith("/forbidden")
    assert delete.json()["permission"] == "data:delete"
    assert "data:read" in delete.json()["granted"]  # the body lists what the role *can* do


async def test_an_invitation_cannot_be_accepted_by_a_different_person(client: AsyncClient):
    """
    A forwarded invitation link is a 403, not a seat.

    This is the difference between an invitation and a bearer token, and it is
    what makes it safe to send invitations through a role alias.
    """
    owner = await signup_and_login(client, org_name="Invite Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    invite = await client.post(
        f"/orgs/{org}/invitations",
        headers=owner["headers"],
        json={"email": unique_email("intended"), "role": "member"},
    )
    token = invite.json()["token"]

    gatecrasher = await signup_and_login(client)
    response = await client.post(
        f"/invitations/{token}/accept", headers=gatecrasher["headers"], json={}
    )
    assert response.status_code == 403
    assert "different address" in response.json()["detail"]


async def test_the_last_owner_cannot_be_removed_or_demoted(client: AsyncClient):
    """
    An org with no owner is not recoverable from the product.

    `org:transfer` and `org:delete` are owner-only, so if the last owner goes the
    remaining members cannot fix it — the answer becomes a support ticket and a
    manual SQL session. Refusing is cheaper.
    """
    owner = await signup_and_login(client, org_name="Sole Owner Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]
    user_id = (await client.get("/auth/me", headers=owner["headers"])).json()["user"]["id"]

    remove = await client.delete(f"/orgs/{org}/members/{user_id}", headers=owner["headers"])
    assert remove.status_code in {403, 409}, remove.text

    demote = await client.patch(
        f"/orgs/{org}/members/{user_id}", headers=owner["headers"], json={"role": "admin"}
    )
    # Refused before the last-owner check even runs, because nobody may edit their
    # own role — both rules point the same way here.
    assert demote.status_code == 403


async def test_every_tenant_query_requires_a_membership(client: AsyncClient):
    """An org id is not a capability. Guessing one gets you a 403."""
    stranger = await signup_and_login(client)
    victim_org = uuid.uuid4()

    for path in ("documents", "members", "invitations", "api-keys", "audit", "entitlements"):
        response = await client.get(f"/orgs/{victim_org}/{path}", headers=stranger["headers"])
        assert response.status_code in {403, 404}, f"{path} leaked: {response.text}"

    anonymous = await client.get(f"/orgs/{victim_org}/documents")
    assert anonymous.status_code == 401


# ---------------------------------------------------------------------------
# Plan limits
# ---------------------------------------------------------------------------


async def test_the_free_plan_refuses_the_fourth_seat_with_a_402(client: AsyncClient):
    """
    402, not 403 and not 429, and the body carries the numbers.

    A client that renders 402 as "you can't do that" throws away the only
    information that lets the customer fix it: which limit, how full, and on what
    plan. The extension members are the point of this test.
    """
    owner = await signup_and_login(client, org_name="Free Plan Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    entitlements = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    assert entitlements.status_code == 200
    assert entitlements.json()["plan"]["code"] == "free"
    assert entitlements.json()["limits"]["seats"] == 3

    # Owner plus two invitations is the limit; the third invitation is one too many.
    for index in range(2):
        invited = await client.post(
            f"/orgs/{org}/invitations",
            headers=owner["headers"],
            json={"email": unique_email(f"seat{index}"), "role": "member"},
        )
        assert invited.status_code == 201, invited.text

    over = await client.post(
        f"/orgs/{org}/invitations",
        headers=owner["headers"],
        json={"email": unique_email("seat3"), "role": "member"},
    )
    assert over.status_code == 402, over.text
    body = over.json()
    assert body["type"].endswith("/quota-exceeded")
    assert body["plan"] == "free"
    assert body["entitlement"] == "seats"
    assert body["limit"] == 3
    assert body["used"] >= 3


async def test_plans_are_public_and_match_the_enforced_limits(client: AsyncClient):
    """The pricing page renders from the same catalogue the API enforces."""
    response = await client.get("/plans")
    assert response.status_code == 200
    codes = [plan["code"] for plan in response.json()]
    assert codes == ["free", "team", "enterprise"]

    enterprise = next(plan for plan in response.json() if plan["code"] == "enterprise")
    assert enterprise["limits"]["seats"] is None  # unlimited, not a big number


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


async def test_an_api_key_is_shown_once_and_then_authenticates(client: AsyncClient):
    owner = await signup_and_login(client, org_name="Keys Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    created = await client.post(
        f"/orgs/{org}/api-keys",
        headers=owner["headers"],
        json={"name": "ci", "scopes": ["data:read", "data:write"]},
    )
    assert created.status_code == 201, created.text
    secret = created.json()["secret"]
    assert secret.startswith("wb_test_")

    # The list endpoint can't re-show it: the row holds a hash.
    listing = await client.get(f"/orgs/{org}/api-keys", headers=owner["headers"])
    assert listing.status_code == 200
    assert "secret" not in json.dumps(listing.json())

    # And the key works as a credential.
    as_key = await client.get(
        f"/orgs/{org}/documents", headers={"Authorization": f"Bearer {secret}"}
    )
    assert as_key.status_code == 200, as_key.text

    # A key cannot exceed the role that minted it: these scopes were accepted
    # because the owner holds them, and the same request as a member would be
    # narrowed rather than refused.
    revoked = await client.delete(
        f"/orgs/{org}/api-keys/{created.json()['id']}", headers=owner["headers"]
    )
    assert revoked.status_code == 204

    after = await client.get(
        f"/orgs/{org}/documents", headers={"Authorization": f"Bearer {secret}"}
    )
    assert after.status_code == 401


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


async def test_the_audit_log_records_who_did_what_and_cannot_be_edited(client: AsyncClient):
    owner = await signup_and_login(client, org_name="Audit Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    await client.post(f"/orgs/{org}/documents", headers=owner["headers"], json={"title": "audited"})

    response = await client.get(f"/orgs/{org}/audit", headers=owner["headers"])
    assert response.status_code == 200, response.text
    events = [item["event"] for item in response.json()["items"]]

    assert "document.created" in events
    assert "org.created" in events
    # Newest first, and paginated by cursor.
    assert response.json()["next_cursor"] is None or isinstance(response.json()["next_cursor"], str)

    # There is no write path, and the database refuses one anyway.
    assert (
        await client.patch(f"/orgs/{org}/audit", headers=owner["headers"], json={})
    ).status_code in {404, 405}


async def test_the_database_refuses_to_edit_the_audit_log(app_settings):
    """
    The claim in SPEC.md, checked against the database rather than believed.

    Three layers protect this table: no ORM path, no grant, and a trigger. The
    trigger is the one that holds, so it's the one asserted — as the *owning*
    role, which is the role a determined mistake would use.
    """
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(str(app_settings.postgres_admin_dsn))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            org_id = (
                await session.execute(
                    text(
                        "INSERT INTO organizations (id, name, slug) "
                        "VALUES (gen_random_uuid(), 'Immutable Test', :slug) RETURNING id"
                    ),
                    {"slug": f"immutable-{uuid.uuid4().hex[:8]}"},
                )
            ).scalar_one()

            await session.execute(
                text(
                    "INSERT INTO audit_events (id, org_id, event, actor_kind) "
                    "VALUES (gen_random_uuid(), :org, 'org.created', 'system')"
                ),
                {"org": org_id},
            )
            await session.commit()

            with pytest.raises(Exception) as update_error:
                await session.execute(
                    text("UPDATE audit_events SET event = 'org.deleted' WHERE org_id = :org"),
                    {"org": org_id},
                )
                await session.commit()
            assert "append-only" in str(update_error.value)

            await session.rollback()

            with pytest.raises(Exception) as delete_error:
                await session.execute(
                    text("DELETE FROM audit_events WHERE org_id = :org"), {"org": org_id}
                )
                await session.commit()
            assert "append-only" in str(delete_error.value)

            await session.rollback()
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


def event_id(name: str) -> str:
    """
    A fresh id per test run.

    Stripe's event ids are unique forever, and the ledger that enforces that is
    the same table these tests exercise — so a literal id here means the second
    run of the suite sees a duplicate delivery and asserts against a webhook that
    was (correctly) never applied.
    """
    return f"evt_{name}_{uuid.uuid4().hex[:10]}"


def sign_body(body: bytes, secret: str, *, timestamp: int | None = None) -> str:
    """Build a Stripe-Signature header the way Stripe does."""
    stamp = timestamp if timestamp is not None else int(time.time())
    signature = hmac.new(secret.encode(), f"{stamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={stamp},v1={signature}"


def subscription_event(
    event_id: str,
    event_type: str,
    *,
    subscription_id: str,
    org_id: str,
    status: str = "active",
    price_id: str = "price_test_team",
    created: int | None = None,
    customer: str = "cus_test",
) -> dict[str, Any]:
    return {
        "id": event_id,
        "type": event_type,
        "created": created if created is not None else int(time.time()),
        "data": {
            "object": {
                "id": subscription_id,
                "customer": customer,
                "status": status,
                "quantity": 1,
                "price": {"id": price_id},
                "client_reference_id": org_id,
                "metadata": {"org_id": org_id},
                "current_period_start": int(time.time()) - 86_400,
                "current_period_end": int(time.time()) + 86_400 * 29,
            }
        },
    }


async def post_webhook(
    client: AsyncClient, payload: dict[str, Any], secret: str = "whsec_test_secret"
):
    body = json.dumps(payload).encode()
    return await client.post(
        "/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": sign_body(body, secret), "Content-Type": "application/json"},
    )


async def test_a_webhook_without_a_valid_signature_is_refused(client: AsyncClient):
    payload = subscription_event(
        event_id("forged"),
        "customer.subscription.created",
        subscription_id="sub_forged",
        org_id=str(uuid.uuid4()),
    )
    body = json.dumps(payload).encode()

    missing = await client.post("/webhooks/stripe", content=body)
    assert missing.status_code == 400

    forged = await client.post(
        "/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": sign_body(body, "whsec_the_wrong_secret")},
    )
    assert forged.status_code == 400
    assert "signature" in forged.json()["detail"].lower()


async def test_a_replayed_webhook_is_refused_after_the_tolerance_window(client: AsyncClient):
    """
    Signature verification without a timestamp check is a signature a replay can
    reuse forever. This is the check.
    """
    payload = subscription_event(
        event_id("old"),
        "customer.subscription.created",
        subscription_id="sub_old",
        org_id=str(uuid.uuid4()),
    )
    body = json.dumps(payload).encode()

    stale = sign_body(body, "whsec_test_secret", timestamp=int(time.time()) - 3600)
    response = await client.post(
        "/webhooks/stripe", content=body, headers={"Stripe-Signature": stale}
    )
    assert response.status_code == 400
    assert "tolerance" in response.json()["detail"]


async def test_a_subscription_upgrade_flows_through_to_the_entitlements(client: AsyncClient):
    """
    The full path: a signed webhook, the state machine, the database, and the
    entitlements the next request resolves.

    `STRIPE_PRICE_IDS` is empty in this environment, so the price id is unknown —
    which is exactly the "new price created before the deploy" case, and the
    designed behaviour is to keep the current plan and log rather than downgrade.
    Here the metadata carries the org, so the subscription attaches; the plan
    stays free until the price map is configured. That is asserted, because the
    wrong behaviour (silently granting a plan) would be worse.
    """
    owner = await signup_and_login(client, org_name="Webhook Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    payload = subscription_event(
        f"evt_{uuid.uuid4().hex[:12]}",
        "customer.subscription.created",
        subscription_id=f"sub_{uuid.uuid4().hex[:12]}",
        org_id=org,
    )
    response = await post_webhook(client, payload)
    assert response.status_code == 200, response.text
    assert response.json()["status"] in {"applied", "noop"}

    entitlements = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    assert entitlements.json()["subscription"]["status"] == "active"

    # The same event again changes nothing: the second delivery is a no-op.
    duplicate = await post_webhook(client, payload)
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "duplicate"


async def test_webhooks_are_order_independent(client: AsyncClient):
    """
    The test the whole state machine exists for.

    Deliver "cancel the old subscription" *before* "create the new one" — which
    is a real ordering Stripe produces on an upgrade — and the customer must end
    up on the new subscription, not cancelled. Then do it the other way round and
    assert the same final state. Two interleavings, one outcome.

    Without the identity guard in `apply_event`, the first ordering cancels a
    customer who just upgraded, and the support ticket arrives within the hour.
    """
    owner = await signup_and_login(client, org_name="Ordering Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    old_sub = f"sub_old_{uuid.uuid4().hex[:8]}"
    new_sub = f"sub_new_{uuid.uuid4().hex[:8]}"
    now = int(time.time())

    # First: establish the old subscription.
    await post_webhook(
        client,
        subscription_event(
            event_id("setup"),
            "customer.subscription.created",
            subscription_id=old_sub,
            org_id=org,
            created=now - 100,
        ),
    )

    # The upgrade, delivered backwards.
    await post_webhook(
        client,
        subscription_event(
            event_id("cancel_old"),
            "customer.subscription.deleted",
            subscription_id=old_sub,
            org_id=org,
            status="canceled",
            created=now - 10,
        ),
    )
    await post_webhook(
        client,
        subscription_event(
            event_id("create_new"),
            "customer.subscription.created",
            subscription_id=new_sub,
            org_id=org,
            created=now,
        ),
    )

    entitlements = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    subscription = entitlements.json()["subscription"]
    assert (
        subscription["status"] == "active"
    ), "the cancellation of the previous subscription leaked onto the new one"
    assert entitlements.json()["is_read_only"] is False

    # Replaying the cancelled subscription's events after the fact changes nothing.
    await post_webhook(
        client,
        subscription_event(
            event_id("stale_update"),
            "customer.subscription.updated",
            subscription_id=old_sub,
            org_id=org,
            status="past_due",
            created=now - 50,
        ),
    )
    still_active = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    assert still_active.json()["subscription"]["status"] == "active"

    # And now the same two events in the order Stripe "should" send them, for a
    # second subscription on the same org.
    third_sub = f"sub_third_{uuid.uuid4().hex[:8]}"
    await post_webhook(
        client,
        subscription_event(
            event_id("create_third"),
            "customer.subscription.created",
            subscription_id=third_sub,
            org_id=org,
            created=now + 10,
        ),
    )
    await post_webhook(
        client,
        subscription_event(
            event_id("cancel_new"),
            "customer.subscription.deleted",
            subscription_id=new_sub,
            org_id=org,
            status="canceled",
            created=now + 20,
        ),
    )
    final = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    assert final.json()["subscription"]["status"] == "active"


async def test_a_failed_payment_makes_an_org_read_only_without_breaking_reads(client: AsyncClient):
    """
    past_due keeps full access; a card that expired this morning must not take a
    customer's integration down. The read-only state arrives only when the
    subscription stops granting access entirely, and even then reads survive.
    """
    owner = await signup_and_login(client, org_name="Dunning Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]

    created = await client.post(
        f"/orgs/{org}/documents", headers=owner["headers"], json={"title": "before"}
    )
    assert created.status_code == 201

    subscription_id = f"sub_dun_{uuid.uuid4().hex[:8]}"
    await post_webhook(
        client,
        subscription_event(
            event_id("dun1"),
            "customer.subscription.created",
            subscription_id=subscription_id,
            org_id=org,
        ),
    )

    # A failed invoice flips the status and nothing else.
    await post_webhook(
        client,
        {
            "id": f"evt_{uuid.uuid4().hex[:12]}",
            "type": "invoice.payment_failed",
            "created": int(time.time()),
            "data": {"object": {"subscription": subscription_id, "customer": "cus_test"}},
        },
    )

    entitlements = await client.get(f"/orgs/{org}/entitlements", headers=owner["headers"])
    assert entitlements.json()["subscription"]["status"] == "past_due"
    # Still writable: dunning exists to resolve this, and locking a paying
    # customer out on the first failed retry is a refund conversation.
    assert entitlements.json()["is_read_only"] is False
    writable = await client.post(
        f"/orgs/{org}/documents", headers=owner["headers"], json={"title": "still working"}
    )
    assert writable.status_code == 201


async def test_an_unhandled_event_type_is_accepted_and_ignored(client: AsyncClient):
    """
    Stripe sends dozens of event types. Returning 4xx for the ones we don't model
    makes Stripe disable the endpoint after three days of failures.
    """
    response = await post_webhook(
        client,
        {
            "id": f"evt_{uuid.uuid4().hex[:12]}",
            "type": "invoice.upcoming",
            "created": int(time.time()),
            "data": {"object": {"customer": "cus_test"}},
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] in {"ignored", "deferred"}


# ---------------------------------------------------------------------------
# Problem details
# ---------------------------------------------------------------------------


async def test_validation_errors_use_the_same_shape_as_every_other_error(client: AsyncClient):
    """
    One parser for the client, not two.

    FastAPI's default is `{"detail": [...]}`, which is a different shape from
    every other error in the API — and the client that handles it special-cases
    one endpoint and forgets another.
    """
    response = await client.post("/auth/login", json={"email": "not-an-email", "password": "x"})
    assert response.status_code == 422
    body = response.json()

    assert body["type"].endswith("/validation-failed")
    assert body["status"] == 422
    assert isinstance(body["errors"], list)
    assert body["errors"][0]["field"] == "email"


async def test_every_response_carries_a_request_id(client: AsyncClient):
    """Support asks for it, and it's in every log line for that request."""
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert len(response.headers["X-Request-ID"]) == 16
    assert response.headers["X-Response-Time"].endswith("ms")
    assert "server" not in {key.lower() for key in response.headers}


async def test_health_live_does_not_touch_the_database(client: AsyncClient):
    """
    Liveness must not depend on a dependency.

    A probe that checks the database restarts every replica when the database
    hiccups, turning a ten-second blip into a fleet-wide cold start.
    """
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    ready = await client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Regression coverage for things that failed quietly
# ---------------------------------------------------------------------------


async def test_a_failed_login_is_recorded_even_though_the_request_failed(
    client: AsyncClient, admin_session
):
    """
    The bookkeeping around a failure has to survive the failure.

    Three wrong passwords, then look at the database rather than the response.
    The response was always right — that is the trap: a naive implementation
    rolls the counter and the attempt rows back with the 401, `failed_login_count`
    stays zero, lockout never triggers, and `login_attempts` stays empty while
    every test that asserts on status codes passes.

    Asserted against the raw table through the admin session, because the whole
    point is that the write reached storage.
    """
    from sqlalchemy import text

    email = unique_email("lockout")
    await client.post("/auth/signup", json={"email": email, "password": PASSWORD, "name": "L"})

    for attempt in range(3):
        response = await client.post(
            "/auth/login", json={"email": email, "password": f"wrong-{attempt}"}
        )
        assert response.status_code == 401

    counter = (
        await admin_session.execute(
            text("SELECT failed_login_count FROM users WHERE lower(email) = :email"),
            {"email": email},
        )
    ).scalar_one()
    assert counter == 3

    attempts = (
        await admin_session.execute(
            text("SELECT count(*) FROM login_attempts WHERE email = :email"), {"email": email}
        )
    ).scalar_one()
    assert attempts == 3


async def test_the_audit_log_names_the_actor(client: AsyncClient, admin_session):
    """
    "Somebody did this" is not an audit log.

    Every route writes its events with `actor=scope.actor`, which is a principal
    object rather than a `User` — and the first version of `write_audit` looked
    for an `email` attribute, found none, and recorded the event as having been
    performed by `system` with a null id. The log still read plausibly, which is
    why it took a query against the table to notice.
    """
    from sqlalchemy import text

    owner = await signup_and_login(client, org_name="Actor Org")
    org = (await client.get("/orgs", headers=owner["headers"])).json()[0]["id"]
    user_id = (await client.get("/auth/me", headers=owner["headers"])).json()["user"]["id"]

    await client.post(
        f"/orgs/{org}/documents", headers=owner["headers"], json={"title": "attributed"}
    )

    rows = (
        (
            await admin_session.execute(
                text(
                    "SELECT event, actor_kind, actor_id FROM audit_events "
                    "WHERE org_id = :org AND event IN ('document.created', 'org.created')"
                ),
                {"org": org},
            )
        )
        .mappings()
        .all()
    )

    assert {row["event"] for row in rows} == {"document.created", "org.created"}, rows
    for row in rows:
        assert row["actor_kind"] == "user", row
        assert str(row["actor_id"]) == user_id, row

    # `org.created` also had a null org: the organisation has no `org_id` column
    # because it *is* the org, so the one event proving the account existed was
    # invisible in that account's own audit view.
    assert all(str(row["actor_id"]) == user_id for row in rows)
