"""
Organisations, members, invitations, API keys, audit.

Five resources in one file because they share one thing: every route in here is
scoped to `{org_id}` in the path, and the permission it needs is the only thing
that differs. Splitting them across modules would spread that pattern over
several files and make it harder to see that none of them forgets it. The
exception is the sample tenant resource — the documents — which lives in
`workbench.data.router` next to its model, because it is the one resource whose
job is to demonstrate the tenant boundary rather than to administer the org.

The two rules that shaped the design:

  **Nothing trusts a body.** No request schema in this file has an `org_id`
  field, and where one accepts a role it is checked against the caller's rank
  with `outranks`. A member cannot invite an admin, and nobody can edit their own
  role — including an owner, because that is how an owner accidentally demotes
  themselves out of their own account.

  **The last owner is protected.** Deleting the final owner is refused, and so
  is demoting them. An org with no owner is a support ticket, a manual SQL
  session, and a customer who can't be billed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import delete, func, select

from workbench.api.deps import (
    PersonDep,
    Scope,
    SystemDep,
    UserDep,
    client_ip,
    get_settings_dep,
    load_entitlements,
    requires,
)
from workbench.api.errors import BadRequest, Conflict, Forbidden, Gone, NotFound
from workbench.api.pagination import Cursor, apply_cursor, build_page, clamp_limit
from workbench.api.schemas import (
    AcceptInvitationRequest,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    AuditEventOut,
    DeletedOut,
    InvitationOut,
    InviteRequest,
    MemberOut,
    OrgCreate,
    OrgOut,
    OrgUpdate,
    OrgWithRole,
    RoleUpdate,
    TransferRequest,
)
from workbench.audit.log import write_audit
from workbench.audit.models import AuditEvent
from workbench.auth.models import ApiKey, User
from workbench.auth.service import AuthError, create_api_key, create_organization
from workbench.core.db import CREDENTIAL_SETTING, set_credential
from workbench.core.models import uuid7
from workbench.core.permissions import assignable_roles, outranks
from workbench.core.settings import Settings
from workbench.email.sender import enqueue
from workbench.tenancy.models import Invitation, Membership, Organization

router = APIRouter(tags=["organisations"])

SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------


@router.post(
    "/orgs",
    response_model=OrgWithRole,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organisation",
)
async def create_org(
    payload: OrgCreate, request: Request, principal: PersonDep, scope: SystemDep
) -> OrgWithRole:
    """
    Creating an org is the one thing a user with no memberships can do.

    Which is why it doesn't go through `requires(...)`: there is no org to hold a
    permission in yet. The creator becomes the owner in the same transaction, so
    the org never exists without somebody who can administer it.
    """
    user = principal.user
    assert user is not None

    try:
        org = await create_organization(
            scope.session,
            name=payload.name,
            slug=payload.slug,
            owner=user,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except AuthError as exc:
        raise Conflict(exc.message) from exc

    return OrgWithRole(**OrgOut.model_validate(org).model_dump(), role="owner")


@router.get("/orgs", response_model=list[OrgWithRole], summary="Organisations you belong to")
async def list_orgs(principal: UserDep, scope: SystemDep) -> list[OrgWithRole]:
    """
    Read through memberships, not through `organizations`.

    The policy on `organizations` would let this work as a plain select — a user
    can see the orgs they belong to — but going through `memberships` also
    returns the role, and it is the same query either way.
    """
    rows = (
        await scope.session.execute(
            select(Organization, Membership.role)
            .join(Membership, Membership.org_id == Organization.id)
            .where(Membership.user_id == principal.actor_id, Membership.suspended_at.is_(None))
            .order_by(Organization.created_at)
        )
    ).all()
    return [OrgWithRole(**OrgOut.model_validate(org).model_dump(), role=role) for org, role in rows]


@router.get("/orgs/{org_id}", response_model=OrgOut)
async def get_org(scope: Annotated[Scope, Depends(requires("org:read"))]) -> OrgOut:
    assert scope.org is not None
    return OrgOut.model_validate(scope.org)


@router.patch("/orgs/{org_id}", response_model=OrgOut)
async def update_org(
    payload: OrgUpdate,
    request: Request,
    scope: Annotated[Scope, Depends(requires("org:update", write=True))],
) -> OrgOut:
    """
    `exclude_unset` matters: `{"name": null}` and `{}` are different requests.

    Sending the whole object back from a form is normal client behaviour, and
    treating every absent field as "set to null" turns a partial update into a
    wipe.
    """
    org = scope.org
    assert org is not None
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        return OrgOut.model_validate(org)

    before = {key: getattr(org, key) for key in changes}
    for key, value in changes.items():
        setattr(org, key, value)

    await write_audit(
        scope.session,
        event="org.updated",
        actor=scope.actor,
        target=org,
        before=before,
        after=changes,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return OrgOut.model_validate(org)


@router.delete("/orgs/{org_id}", response_model=DeletedOut)
async def delete_org(
    request: Request,
    scope: Annotated[Scope, Depends(requires("org:delete", write=True))],
    hard: Annotated[bool, Query(description="Really delete, rather than deactivate")] = False,
) -> DeletedOut:
    """
    Soft by default. `?hard=true` is a real delete, and it cascades.

    Soft is the default because the common case is a customer who wants their
    workspace out of the way, and the uncommon case is a GDPR erasure request
    with a legal deadline. The first should be reversible for thirty days; the
    second should not be a checkbox in the UI.
    """
    org = scope.org
    assert org is not None

    if not hard:
        org.is_active = False
        await write_audit(
            scope.session,
            event="org.deleted",
            actor=scope.actor,
            target=org,
            after={"hard": False},
            ip_address=client_ip(request),
        )
        return DeletedOut(id=org.id, deleted=True, hard=False)

    # A hard delete of the last org a sole owner belongs to leaves them with an
    # account and nothing in it. That is fine. What is not fine is a support
    # process that can't reverse a soft delete, which is why the audit event
    # records which one happened.
    org_id = org.id
    await write_audit(
        scope.session,
        event="org.deleted",
        actor=scope.actor,
        target=org,
        after={"hard": True, "slug": org.slug},
        ip_address=client_ip(request),
    )
    await scope.session.execute(delete(Organization).where(Organization.id == org_id))
    return DeletedOut(id=org_id, deleted=True, hard=True)


@router.post("/orgs/{org_id}/transfer", response_model=OrgOut)
async def transfer_ownership(
    payload: TransferRequest,
    request: Request,
    scope: Annotated[Scope, Depends(requires("org:transfer", write=True))],
) -> OrgOut:
    """
    Hand the org to somebody else.

    The target has to be an admin already: transferring to a viewer would give
    that person the org *and* leave the previous owner unable to undo it, because
    they would no longer hold `org:transfer`.
    """
    org = scope.org
    assert org is not None

    target = (
        await scope.session.execute(
            select(Membership).where(
                Membership.org_id == org.id, Membership.user_id == payload.to_user_id
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise NotFound("membership", payload.to_user_id)
    if target.role != "admin":
        raise BadRequest(
            "ownership can only be transferred to an admin of this organisation — "
            "promote them first, so the change is visible in the audit log on its own"
        )

    current = (
        (
            await scope.session.execute(
                select(Membership).where(Membership.org_id == org.id, Membership.role == "owner")
            )
        )
        .scalars()
        .all()
    )
    previous = [m.user_id for m in current]

    for membership in current:
        membership.role = "admin"
    target.role = "owner"

    await write_audit(
        scope.session,
        event="org.ownership_transferred",
        actor=scope.actor,
        target=org,
        before={"owners": [str(user_id) for user_id in previous]},
        after={"owners": [str(target.user_id)]},
        ip_address=client_ip(request),
    )
    return OrgOut.model_validate(org)


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/members", response_model=list[MemberOut])
async def list_members(
    scope: Annotated[Scope, Depends(requires("member:read"))],
) -> list[MemberOut]:
    rows = (
        await scope.session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.org_id == scope.org_id)
            .order_by(Membership.joined_at)
        )
    ).all()
    return [
        MemberOut(
            user_id=user.id,
            email=user.email,
            name=user.name,
            role=membership.role,
            joined_at=membership.joined_at,
            last_login_at=user.last_login_at,
            is_active=user.is_active and membership.suspended_at is None,
        )
        for membership, user in rows
    ]


@router.patch("/orgs/{org_id}/members/{user_id}", response_model=MemberOut)
async def update_member_role(
    user_id: uuid.UUID,
    payload: RoleUpdate,
    request: Request,
    scope: Annotated[Scope, Depends(requires("member:update_role", write=True))],
) -> MemberOut:
    """
    Change somebody's role, within your own rank.

    Three refusals, each of which is a real incident avoided:

      * you cannot edit yourself — an owner demoting themselves leaves the org
        ownerless, and there is no "undo" they still have permission to press
      * you cannot grant a role at or above yours (`outranks`, strictly)
      * you cannot demote someone at or above you
    """
    membership = await _membership(scope, user_id)

    actor_role = scope.role or "viewer"
    if membership.user_id == scope.actor_id:
        raise Forbidden(
            "you cannot change your own role — ask another admin, or transfer " "ownership first"
        )
    if not outranks(actor_role, membership.role) or not outranks(actor_role, payload.role):
        raise Forbidden(
            f"a {actor_role} cannot change a {membership.role} to {payload.role}: "
            "you may only act on roles below your own"
        )
    if payload.role not in assignable_roles(actor_role):
        raise Forbidden(f"a {actor_role} may assign: {', '.join(assignable_roles(actor_role))}")

    if membership.role == "owner" and payload.role != "owner":
        await _refuse_if_last_owner(scope, membership, action="demote")

    before = membership.role
    membership.role = payload.role

    await write_audit(
        scope.session,
        event="member.role_changed",
        actor=scope.actor,
        org_id=scope.org_id,
        target=membership,
        target_type="membership",
        target_id=str(membership.user_id),
        before={"role": before},
        after={"role": payload.role},
        ip_address=client_ip(request),
    )

    user = (
        await scope.session.execute(select(User).where(User.id == membership.user_id))
    ).scalar_one()
    return MemberOut(
        user_id=user.id,
        email=user.email,
        name=user.name,
        role=membership.role,
        joined_at=membership.joined_at,
        last_login_at=user.last_login_at,
    )


@router.delete("/orgs/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: uuid.UUID,
    request: Request,
    scope: Annotated[Scope, Depends(requires("member:remove", write=True))],
) -> Response:
    """
    Remove somebody. The last owner cannot be removed, by anyone.

    An org with no members is recoverable — an admin can re-invite. An org with
    no *owner* is not: `org:transfer` and `org:delete` are owner-only, so nobody
    left can fix it from the product.
    """
    membership = await _membership(scope, user_id)

    if not outranks(scope.role or "viewer", membership.role):
        raise Forbidden("you may only remove members whose role is below your own")
    if membership.role == "owner":
        await _refuse_if_last_owner(scope, membership, action="remove")

    await write_audit(
        scope.session,
        event="member.removed",
        actor=scope.actor,
        org_id=scope.org_id,
        target=membership,
        target_type="membership",
        target_id=str(membership.user_id),
        before={"role": membership.role},
        ip_address=client_ip(request),
    )
    await scope.session.execute(delete(Membership).where(Membership.id == membership.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _membership(scope: Scope, user_id: uuid.UUID) -> Membership:
    membership = (
        await scope.session.execute(
            select(Membership).where(
                Membership.org_id == scope.org_id, Membership.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        raise NotFound("member", user_id)
    return membership


async def _refuse_if_last_owner(scope: Scope, membership: Membership, *, action: str) -> None:
    owners = (
        await scope.session.execute(
            select(func.count())
            .select_from(Membership)
            .where(Membership.org_id == scope.org_id, Membership.role == "owner")
        )
    ).scalar_one()
    if owners <= 1:
        raise Conflict(
            f"you cannot {action} the last owner of an organisation — transfer ownership "
            "to somebody else first. Without an owner, nobody can transfer it back, "
            "because that permission is owner-only."
        )


# ---------------------------------------------------------------------------
# Invitations
# ---------------------------------------------------------------------------


@router.post(
    "/orgs/{org_id}/invitations",
    response_model=InvitationOut,
    status_code=status.HTTP_201_CREATED,
)
async def invite_member(
    payload: InviteRequest,
    request: Request,
    scope: Annotated[Scope, Depends(requires("member:invite", write=True))],
    settings: SettingsDep,
) -> InvitationOut:
    """
    Invite somebody, if there is a seat for them.

    The seat check happens here, before the email is sent, and it uses the plan's
    limit rather than the org's opinion of it. A free org at three seats gets a
    402 explaining the plan, not a 500 from a database constraint an hour later
    when the third person clicks the link.
    """
    if not outranks(scope.role or "viewer", payload.role):
        raise Forbidden(f"a {scope.role} cannot invite a {payload.role}")

    org = scope.org
    assert org is not None

    # How many people this org has already promised a seat to. Counted before the
    # quota check, because a pending invitation is a seat as far as the plan is
    # concerned: the alternative is telling somebody "yes, invite your team" and
    # then refusing their colleague's click.
    pending = (
        await scope.session.execute(
            select(func.count())
            .select_from(Invitation)
            .where(
                Invitation.org_id == org.id,
                Invitation.accepted_at.is_(None),
                Invitation.revoked_at.is_(None),
            )
        )
    ).scalar_one()

    assert scope.entitlements is not None
    scope.entitlements.require_with_reserved("seats", pending)
    if pending >= settings.invitation_max_pending_per_org:
        raise Conflict(
            f"this organisation already has {pending} pending invitations; "
            "revoke some before sending more"
        )

    email = User.normalise_email(str(payload.email))

    # Already a member? Say so plainly — unlike login, there is no enumeration
    # cost here, because only somebody who can invite is asking.
    existing = (
        await scope.session.execute(
            select(Membership)
            .join(User, User.id == Membership.user_id)
            .where(Membership.org_id == org.id, User.email == email)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise Conflict("that address is already a member of this organisation")

    token, token_hash = Invitation.new_token()
    invitation = Invitation(
        id=uuid7(),
        org_id=org.id,
        email=email,
        role=payload.role,
        token_hash=token_hash,
        expires_at=Invitation.default_expiry(settings.invitation_ttl_hours),
        invited_by_id=scope.actor_id or uuid7(),
    )
    scope.session.add(invitation)
    await scope.session.flush()

    await write_audit(
        scope.session,
        event="member.invited",
        actor=scope.actor,
        org_id=org.id,
        target=invitation,
        after={"email": email, "role": payload.role},
        ip_address=client_ip(request),
    )

    inviter = scope.principal.user
    enqueue(
        "invitation",
        to=email,
        org_name=org.name,
        inviter_name=inviter.name or inviter.email if inviter else "A teammate",
        role=payload.role,
        note=payload.note,
        accept_url=f"{settings.app_base_url}/invitations/{token}",
        expires_at=invitation.expires_at.strftime("%d %B %Y"),
        email=email,
    )

    return InvitationOut(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        invited_by_id=invitation.invited_by_id,
        # Returned here and nowhere else, ever: the row holds a hash.
        token=token,
    )


@router.get("/orgs/{org_id}/invitations", response_model=list[InvitationOut])
async def list_invitations(
    scope: Annotated[Scope, Depends(requires("member:read"))],
) -> list[InvitationOut]:
    rows = (
        (
            await scope.session.execute(
                select(Invitation)
                .where(Invitation.org_id == scope.org_id, Invitation.revoked_at.is_(None))
                .order_by(Invitation.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    # `token=None` on purpose: the list can't re-show a secret it doesn't have.
    return [
        InvitationOut(
            id=row.id,
            email=row.email,
            role=row.role,
            expires_at=row.expires_at,
            created_at=row.created_at,
            invited_by_id=row.invited_by_id,
            token=None,
        )
        for row in rows
    ]


@router.delete(
    "/orgs/{org_id}/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_invitation(
    invitation_id: uuid.UUID,
    request: Request,
    scope: Annotated[Scope, Depends(requires("member:invite", write=True))],
) -> Response:
    invitation = (
        await scope.session.execute(
            select(Invitation).where(
                Invitation.id == invitation_id, Invitation.org_id == scope.org_id
            )
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise NotFound("invitation", invitation_id)

    invitation.revoke(scope.actor_id or uuid7())
    await write_audit(
        scope.session,
        event="member.invitation_revoked",
        actor=scope.actor,
        org_id=scope.org_id,
        target=invitation,
        ip_address=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/invitations/{token}/accept", response_model=OrgWithRole)
async def accept_invitation(
    token: str,
    payload: AcceptInvitationRequest,
    request: Request,
    principal: PersonDep,
    scope: SystemDep,
    settings: SettingsDep,
) -> OrgWithRole:
    """
    Accept an invitation, as the person it was sent to.

    The token is enough to *find* the invitation and not enough to use it: the
    signed-in address has to match the invited one. A forwarded link is then a
    403 rather than a seat, which is the difference between an invitation and a
    bearer token — and the reason invitations are safe to send through mail
    providers and shared inboxes.

    Accepting as a different person is how an invite sent to a role alias ends up
    granting access to whoever read the alias first.
    """
    user = principal.user
    assert user is not None

    from workbench.auth.passwords import hash_token as _hash_token

    await set_credential(scope.session, CREDENTIAL_SETTING, _hash_token(token))
    invitation = (
        await scope.session.execute(
            select(Invitation).where(Invitation.token_hash == _hash_token(token))
        )
    ).scalar_one_or_none()

    if invitation is None:
        raise NotFound("invitation")
    if invitation.accepted_at is not None:
        raise Conflict("this invitation has already been accepted")
    if invitation.revoked_at is not None:
        raise Gone("this invitation has been revoked")
    if invitation.is_expired:
        raise Gone("this invitation has expired; ask for a new one")
    if invitation.email != User.normalise_email(user.email):
        raise Forbidden(
            "this invitation was sent to a different address; sign in as that user, "
            "or ask for a new invitation"
        )

    # Set the tenant to the org being joined *before* writing the membership,
    # because the policy on `memberships` requires it.
    from workbench.core.db import set_tenant

    await set_tenant(scope.session, invitation.org_id, actor_id=user.id)

    invitation.accept(user.id)
    scope.session.add(
        Membership(
            id=uuid7(),
            org_id=invitation.org_id,
            user_id=user.id,
            role=invitation.role,
            invited_by_id=invitation.invited_by_id,
        )
    )
    org = (
        await scope.session.execute(
            select(Organization).where(Organization.id == invitation.org_id)
        )
    ).scalar_one()

    # The seat limit is checked again here, not only at invite time. The plan can
    # have changed in between — a team that dropped to free still has three
    # pending invitations in flight, and accepting them all would put the org
    # over a limit it can no longer be over on a hard-stop plan.
    entitlements = await load_entitlements(scope.session, org)
    entitlements.require("seats", 1)

    await write_audit(
        scope.session,
        event="member.invitation_accepted",
        actor=user,
        org_id=org.id,
        target=invitation,
        after={"role": invitation.role},
        ip_address=client_ip(request),
    )
    return OrgWithRole(**OrgOut.model_validate(org).model_dump(), role=invitation.role)


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


@router.post(
    "/orgs/{org_id}/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_key(
    payload: ApiKeyCreate,
    scope: Annotated[Scope, Depends(requires("apikey:write", write=True))],
) -> ApiKeyCreated:
    """
    Mint a key. The secret appears in this response and never again.

    A recovery flow for a lost key secret would mean storing something
    recoverable, which means a database dump hands over working credentials.
    Losing the secret costs a new key and a config change; it's the right trade.
    """
    user = scope.principal.user
    if user is None:
        # A key minting a key is how a leaked machine credential becomes a
        # permanent one: the original can be revoked and the child carries on,
        # and nothing in the key list points back at the request that made it.
        # Refused outright rather than narrowed, because there is no version of
        # this that an operator wants to debug later.
        raise Forbidden("an API key cannot create another API key; use an access token")
    scope.require_quota("api_keys", 1)

    try:
        key, secret = await create_api_key(
            scope.session,
            org_id=scope.org_id,
            created_by=user,
            name=payload.name,
            scopes=payload.scopes,
            expires_in_days=payload.expires_in_days,
        )
    except AuthError as exc:
        raise BadRequest(exc.message) from exc

    return ApiKeyCreated(
        **ApiKeyOut.model_validate(key).model_dump(),
        secret=secret,
    )


@router.get("/orgs/{org_id}/api-keys", response_model=list[ApiKeyOut])
async def list_keys(
    scope: Annotated[Scope, Depends(requires("apikey:read"))],
) -> list[ApiKeyOut]:
    rows = (
        (
            await scope.session.execute(
                select(ApiKey)
                .where(ApiKey.org_id == scope.org_id, ApiKey.deleted_at.is_(None))
                .order_by(ApiKey.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [ApiKeyOut.model_validate(row) for row in rows]


@router.delete("/orgs/{org_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    key_id: uuid.UUID,
    request: Request,
    scope: Annotated[Scope, Depends(requires("apikey:write", write=True))],
) -> Response:
    key = (
        await scope.session.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == scope.org_id)
        )
    ).scalar_one_or_none()
    if key is None:
        raise NotFound("API key", key_id)

    key.revoke()
    await write_audit(
        scope.session,
        event="apikey.revoked",
        actor=scope.actor,
        org_id=scope.org_id,
        target=key,
        after={"prefix": key.prefix, "name": key.name},
        ip_address=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/audit", response_model=dict)
async def read_audit(
    scope: Annotated[Scope, Depends(requires("audit:read"))],
    limit: Annotated[int | None, Query(ge=1, le=200)] = None,
    cursor: str | None = None,
    event: str | None = Query(default=None, description="Filter to one event kind"),
    actor_id: uuid.UUID | None = None,
) -> dict:
    """
    Cursor-paginated, newest first, never editable.

    There is no `PUT` and no `DELETE` on this collection and there will not be
    one: the table has a trigger that refuses both, so the endpoint could not be
    written if somebody tried.
    """
    size = clamp_limit(limit)
    statement = select(AuditEvent).where(AuditEvent.org_id == scope.org_id)
    if event:
        statement = statement.where(AuditEvent.event == event)
    if actor_id:
        statement = statement.where(AuditEvent.actor_id == actor_id)
    if cursor:
        statement = apply_cursor(statement, Cursor.decode(cursor), model=AuditEvent)

    statement = statement.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
    rows = (await scope.session.execute(statement.limit(size + 1))).scalars().all()
    page = build_page(rows, size)

    return {
        "items": [AuditEventOut.model_validate(row) for row in page.items],
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "limit": size,
        "count": len(page.items),
    }


@router.get("/orgs/{org_id}/audit/export", response_model=dict)
async def export_audit(
    request: Request,
    scope: Annotated[Scope, Depends(requires("audit:read", feature="audit_export"))],
    since: datetime | None = None,
) -> dict:
    """
    A signed, expiring URL to the whole log.

    Gated on the `audit_export` feature because a full export is the thing
    auditors and procurement ask for, and it is Enterprise on every competitor's
    pricing page for a reason.

    The export itself is a worker job — a customer with two years of history
    should not be waiting on a request that streams a hundred megabytes.
    """
    from workbench.workers.tasks import export_audit_log

    job = export_audit_log.delay(
        org_id=str(scope.org_id),
        requested_by=str(scope.actor_id) if scope.actor_id else None,
        since=since.isoformat() if since else None,
    )
    # 202-shaped: the export is queued, not produced. The client polls the job.
    # Returning a URL to a file that doesn't exist yet is how clients end up
    # showing "preparing your export" forever with no way to tell it failed.
    return {
        "format": "json",
        "job_id": job.id,
        "status_url": f"/orgs/{scope.org_id}/audit/export/{job.id}",
        "queued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


__all__ = ["router"]
