"""
The sample tenant resource.

This is the smallest possible demonstration of what the whole project is about,
and it is worth being explicit about how little code that takes: `list_documents`
has no `WHERE org_id = ...` clause. It does not need one. The session it runs on
is bound to a tenant before the query is issued, the policy on `documents`
filters by that setting, and a row belonging to another organisation is not
visible — not "filtered out", not fetched and then discarded: it is not in the
result set, and it never leaves the database.

Anyone extending this boilerplate should read these four handlers before writing
their own resource. The pattern is:

    scope: Annotated[Scope, Depends(requires("data:read"))]

and the four rules that go with it:

  * the org comes from the path and the scope, never from the body
  * `write=True` is what makes a read-only org (unpaid, cancelled) refuse the
    write with a 402 instead of accepting it and surprising somebody later
  * deletions are soft, because a document that vanishes on the wrong click is a
    support ticket, and `?hard=true` exists for the rare real one
  * a missing row and a row in somebody else's org are the same 404

Split out of `workbench.tenancy.router` once it passed four hundred lines: the
tenancy routes are about administering an organisation and these are about using
one, and the two stop being the same conversation the moment there is a second
resource.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select

from workbench.api.deps import Scope, client_ip, requires
from workbench.api.errors import NotFound
from workbench.api.pagination import Cursor, apply_cursor, build_page, clamp_limit
from workbench.api.schemas import DocumentCreate, DocumentOut, DocumentUpdate
from workbench.audit.log import write_audit
from workbench.core.models import uuid7
from workbench.data.models import Document

router = APIRouter(tags=["documents"])


# ---------------------------------------------------------------------------
# Documents — the sample tenant resource
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/documents", response_model=list[DocumentOut])
async def list_documents(
    scope: Annotated[Scope, Depends(requires("data:read"))],
    limit: Annotated[int | None, Query(ge=1, le=200)] = None,
    cursor: str | None = None,
) -> list[DocumentOut]:
    """
    Note what is missing from the query: a `WHERE org_id = ...` clause.

    It is missing on purpose and it is not a bug. The session is bound to the
    tenant, the policy on `documents` filters by it, and the query below cannot
    see another org's rows even written this way. That is the property worth
    demonstrating — if this endpoint were ever run without a tenant, it would
    return nothing rather than everything.
    """
    statement = select(Document).where(Document.deleted_at.is_(None))
    if cursor:
        statement = apply_cursor(statement, Cursor.decode(cursor), model=Document)
    statement = statement.order_by(Document.created_at.desc(), Document.id.desc())
    rows = (await scope.session.execute(statement.limit(clamp_limit(limit) + 1))).scalars().all()
    return [DocumentOut.model_validate(row) for row in build_page(rows, clamp_limit(limit)).items]


@router.post(
    "/orgs/{org_id}/documents",
    response_model=DocumentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_document(
    payload: DocumentCreate,
    request: Request,
    scope: Annotated[Scope, Depends(requires("data:write", write=True))],
) -> DocumentOut:
    scope.require_quota("requests_this_month", 1)

    document = Document(
        id=uuid7(),
        # From the scope, never from the body. There is no `org_id` field in the
        # request schema, because a field that exists is a field someone will
        # eventually trust.
        org_id=scope.org_id,
        title=payload.title,
        body=payload.body,
        created_by_id=scope.actor_id,
    )
    scope.session.add(document)
    await scope.session.flush()

    await write_audit(
        scope.session,
        event="document.created",
        actor=scope.actor,
        org_id=scope.org_id,
        target=document,
        after={"title": document.title},
        ip_address=client_ip(request),
    )
    return DocumentOut.model_validate(document)


@router.get("/orgs/{org_id}/documents/{document_id}", response_model=DocumentOut)
async def get_document(
    document_id: uuid.UUID,
    scope: Annotated[Scope, Depends(requires("data:read"))],
) -> DocumentOut:
    return DocumentOut.model_validate(await _document(scope, document_id))


@router.patch("/orgs/{org_id}/documents/{document_id}", response_model=DocumentOut)
async def update_document(
    document_id: uuid.UUID,
    payload: DocumentUpdate,
    request: Request,
    scope: Annotated[Scope, Depends(requires("data:write", write=True))],
) -> DocumentOut:
    document = await _document(scope, document_id)
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        return DocumentOut.model_validate(document)

    before = {key: getattr(document, key) for key in changes}
    for key, value in changes.items():
        setattr(document, key, value)

    await write_audit(
        scope.session,
        event="document.updated",
        actor=scope.actor,
        org_id=scope.org_id,
        target=document,
        before=before,
        after=changes,
        ip_address=client_ip(request),
    )
    return DocumentOut.model_validate(document)


@router.delete("/orgs/{org_id}/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: uuid.UUID,
    request: Request,
    scope: Annotated[Scope, Depends(requires("data:delete", write=True))],
) -> Response:
    document = await _document(scope, document_id)
    document.soft_delete()
    await write_audit(
        scope.session,
        event="document.deleted",
        actor=scope.actor,
        org_id=scope.org_id,
        target=document,
        ip_address=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _document(scope: Scope, document_id: uuid.UUID) -> Document:
    document = (
        await scope.session.execute(
            select(Document).where(Document.id == document_id, Document.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if document is None:
        # No `org_id` in the predicate above, and a document belonging to another
        # tenant is invisible rather than refused — same 404 as one that doesn't
        # exist. See the note on `list_documents`.
        raise NotFound("document", document_id)
    return document
