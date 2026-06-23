"""
The authorisation matrix.

One dict. Every route asks `can(role, "billing:write")`. Adding a role is one
entry here, not a grep for `is_admin` across forty files.

Why a matrix instead of boolean flags: `is_admin` starts as one boolean and
within a year you need "can invite but not remove", "can see the invoice but not
change the plan", "can do everything except delete the org". Each of those
becomes another boolean, and then a check has to combine four of them in the
right order. The matrix makes the combination explicit and testable.

Why permissions instead of roles in the check: routes that ask `role ==
"owner"` break the first time a customer needs a fifth role. Routes that ask
`can(role, "org:delete")` don't care how many roles exist.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, Literal, TypedDict, cast, get_args

Role = Literal["owner", "admin", "member", "viewer"]
ROLES: Final[tuple[Role, ...]] = get_args(Role)

# Every permission the system knows about. Kept as a closed set so a typo in a
# route is an error at test time rather than a silent `False` at runtime.
Permission = Literal[
    "org:read",
    "org:update",
    "org:delete",
    "org:transfer",
    "member:read",
    "member:invite",
    "member:update_role",
    "member:remove",
    "billing:read",
    "billing:write",
    "apikey:read",
    "apikey:write",
    "audit:read",
    "data:read",
    "data:write",
    "data:delete",
]
PERMISSIONS: Final[tuple[Permission, ...]] = get_args(Permission)

# Roles are ordered from most to least privileged. Used only for the
# "you cannot outrank yourself" rule — never for permission checks.
ROLE_RANK: Final[dict[str, int]] = {
    "owner": 40,
    "admin": 30,
    "member": 20,
    "viewer": 10,
}

MEMBER_PERMISSIONS: Final[frozenset[Permission]] = frozenset(
    {"org:read", "member:read", "billing:read", "apikey:read", "data:read", "data:write"}
)

MATRIX: Final[dict[Role, frozenset[Permission]]] = {
    "owner": frozenset(PERMISSIONS),
    "admin": frozenset(PERMISSIONS) - {"org:delete", "org:transfer"},
    "member": MEMBER_PERMISSIONS,
    "viewer": frozenset({"org:read", "member:read", "billing:read", "data:read"}),
}


class PermissionDenied(PermissionError):
    """Raised by require()/require_all(). Routers translate this to a 403."""

    def __init__(self, role: str, permission: str) -> None:
        super().__init__(f"role '{role}' does not hold permission '{permission}'")
        self.role = role
        self.permission = permission


def can(role: str | None, permission: Permission) -> bool:
    """True if the role holds the permission. Unknown roles hold nothing."""
    if role is None:
        return False
    return permission in permissions_for(role)


def require(role: str | None, permission: Permission) -> None:
    if not can(role, permission):
        raise PermissionDenied(role or "anonymous", permission)


def require_any(role: str | None, permissions: Iterable[Permission]) -> Permission:
    """Passes if the role holds at least one. Returns which one matched."""
    for permission in permissions:
        if can(role, permission):
            return permission
    raise PermissionDenied(role or "anonymous", " | ".join(permissions))


def permissions_for(role: str) -> frozenset[Permission]:
    """
    The permissions a role holds. An unknown role holds none.

    The cast is not decoration. Roles arrive here as `str` — from a database
    enum, from a JWT claim, from a path parameter — while `MATRIX` is keyed by
    the `Role` literal so that a typo in the table is a type error. Widening the
    lookup is the honest way to bridge that: the runtime behaviour (unknown role
    → no permissions) is exactly what the annotation says.
    """
    return MATRIX.get(cast(Role, role), frozenset())


def outranks(actor: str, target: str) -> bool:
    """
    True when the actor's role is strictly higher than the target's.

    Used to stop an admin demoting an owner, and to stop anyone editing their own
    role. Note `>=` appears nowhere here on purpose: equal ranks can't act on each
    other, which is what you want when two admins are in the same org.
    """
    return ROLE_RANK.get(actor, 0) > ROLE_RANK.get(target, 0)


def is_valid_role(role: str) -> bool:
    return role in MATRIX


def assignable_roles(actor_role: str) -> tuple[str, ...]:
    """Roles this actor is allowed to hand out — strictly below their own."""
    rank = ROLE_RANK.get(actor_role, 0)
    return tuple(r for r in ROLES if ROLE_RANK[r] < rank)


# The shape every consumer of `describe_matrix` receives: the CLI prints it, the
# staff console serves it, and README tables are generated from it. Written down
# once so a new field cannot be added to two of the three.
class PermissionRow(TypedDict):
    permission: Permission
    roles: list[Role]


def describe_matrix() -> list[PermissionRow]:
    """Human-readable matrix. The admin console renders this; docs are generated from it."""
    return [
        PermissionRow(
            permission=permission,
            roles=sorted(role for role in ROLES if can(role, permission)),
        )
        for permission in PERMISSIONS
    ]
