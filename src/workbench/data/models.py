"""
The sample tenant-owned resource.

This table is deliberately boring. It exists for two reasons:

1. The isolation suite needs *something* to leak. Testing row-level security on
   `organizations` would test the policy that has exceptions in it (a user must
   see the orgs they belong to, and must be able to create one); documents has no
   such special case, so a failure there is unambiguous.
2. It is the copyable pattern. Everything a new tenant table needs is here: mix
   in `TenantScoped`, keep `org_id` named exactly that, and the migration helper
   picks it up. A real resource in a real fork of this repo is a template away.

Every write goes through `tenant_session`, so `org_id` is filled from the session
rather than from the request body. A client that posts `{"org_id": "<someone
else's>"}` is ignored, not rejected — the field isn't read.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from workbench.core.models import Base, SoftDelete, TenantScoped, Timestamped, UUIDPrimaryKey


class Document(Base, UUIDPrimaryKey, TenantScoped, Timestamped, SoftDelete):
    __tablename__ = "documents"

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        # Index named in the migration, so it must be named here too or
        # autogenerate will try to create it a second time.
        Index("ix_documents_org_created", "org_id", text("created_at DESC")),
    )

    def __repr__(self) -> str:
        return f"<Document {self.id} org={self.org_id}>"
