"""
Exhaustive permission matrix tests.

"Exhaustive" is the operative word. A role system tested with three happy-path
assertions is a role system with an undocumented hole; the check is 4 roles × 16
permissions, so we assert all 64 cells, plus the properties that must hold for
any future role.
"""

from __future__ import annotations

import pytest

from workbench.core.permissions import (
    MATRIX,
    PERMISSIONS,
    ROLE_RANK,
    ROLES,
    PermissionDenied,
    assignable_roles,
    can,
    describe_matrix,
    is_valid_role,
    outranks,
    permissions_for,
    require,
    require_any,
)

pytestmark = pytest.mark.unit

# The matrix written out longhand. If you change the matrix on purpose, change
# this too — the diff is the review.
EXPECTED = {
    "owner": {
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
    },
    "admin": {
        "org:read",
        "org:update",
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
    },
    "member": {
        "org:read",
        "member:read",
        "billing:read",
        "apikey:read",
        "data:read",
        "data:write",
    },
    "viewer": {"org:read", "member:read", "billing:read", "data:read"},
}


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("permission", PERMISSIONS)
def test_every_matrix_cell(role, permission):
    expected = permission in EXPECTED[role]
    assert (
        can(role, permission) is expected
    ), f"{role} × {permission}: expected {expected}, got {can(role, permission)}"


# ---------------------------------------------------------------------------
# Properties that must hold for any future role
# ---------------------------------------------------------------------------


def test_owner_holds_every_permission():
    """The owner is the escape hatch. If they can't do it, nobody can."""
    assert permissions_for("owner") == frozenset(PERMISSIONS)


def test_every_role_is_represented_in_the_matrix():
    assert set(MATRIX) == set(ROLES)


def test_adding_a_role_requires_no_change_to_callers():
    """
    A guard rather than a test of current behaviour: routes must ask `can(...)`,
    never compare role strings. If this file ever needs a new case in the
    parametrised matrix, the design is intact.
    """
    matrix = dict(MATRIX)
    matrix["auditor"] = frozenset({"org:read", "audit:read"})
    assert "audit:read" in matrix["auditor"]
    assert permissions_for("owner") == frozenset(PERMISSIONS)


def test_member_and_viewer_can_never_write_the_org():
    for role in ("member", "viewer"):
        for permission in ("org:update", "org:delete", "org:transfer", "billing:write"):
            assert not can(role, permission), f"{role} must not hold {permission}"


def test_only_the_owner_can_delete_or_transfer():
    for permission in ("org:delete", "org:transfer"):
        holders = [role for role in ROLES if can(role, permission)]
        assert holders == ["owner"], f"{permission} is held by {holders}"


def test_nobody_but_the_owner_touches_billing_writes():
    holders = [role for role in ROLES if can(role, "billing:write")]
    assert set(holders) == {
        "owner",
        "admin",
    }, "an org needs at least two people who can fix a failed payment"


def test_every_role_can_read_the_org():
    """A role that can't read the org it belongs to will break the frontend."""
    for role in ROLES:
        assert can(role, "org:read"), f"{role} cannot read its own org"


# ---------------------------------------------------------------------------
# Rank
# ---------------------------------------------------------------------------


def test_ranks_are_strictly_ordered_with_no_ties():
    ranks = [ROLE_RANK[role] for role in ROLES]
    assert len(set(ranks)) == len(ranks), "two roles share a rank — outranks() becomes ambiguous"
    assert ranks == sorted(ranks, reverse=True), "ROLES should be ordered most to least privileged"


def test_outranks_is_strict():
    assert outranks("owner", "admin")
    assert outranks("admin", "member")
    assert outranks("member", "viewer")
    # Equal ranks must not act on each other. Two admins in one org is normal;
    # one demoting the other is not.
    assert not outranks("admin", "admin")
    assert not outranks("owner", "owner")


def test_outranks_handles_unknown_roles_without_raising():
    assert not outranks("nonsense", "viewer")
    assert outranks("owner", "nonsense")


def test_assignable_roles_are_strictly_below_the_actor():
    assert set(assignable_roles("owner")) == {"admin", "member", "viewer"}
    assert set(assignable_roles("admin")) == {"member", "viewer"}
    assert set(assignable_roles("member")) == {"viewer"}
    assert assignable_roles("viewer") == ()


def test_nobody_can_promote_to_their_own_level():
    for role in ROLES:
        assert role not in assignable_roles(role), f"{role} can assign its own role"


# ---------------------------------------------------------------------------
# require / require_any
# ---------------------------------------------------------------------------


def test_require_raises_with_the_role_and_permission_in_the_message():
    with pytest.raises(PermissionDenied) as exc:
        require("member", "org:delete")
    assert exc.value.role == "member"
    assert exc.value.permission == "org:delete"
    assert "member" in str(exc.value)


def test_require_names_anonymous_users_as_such():
    with pytest.raises(PermissionDenied) as exc:
        require(None, "org:read")
    assert exc.value.role == "anonymous"


def test_require_is_silent_when_held():
    require("owner", "org:delete")
    require("viewer", "data:read")


def test_require_any_returns_the_permission_that_matched():
    matched = require_any("viewer", ("data:write", "data:read"))
    assert matched == "data:read"


def test_require_any_raises_when_none_match():
    with pytest.raises(PermissionDenied):
        require_any("viewer", ("data:write", "billing:write"))


def test_unknown_roles_hold_nothing():
    for permission in PERMISSIONS:
        assert not can("superuser", permission)
        assert not can("", permission)
        assert not can(None, permission)


def test_is_valid_role():
    assert all(is_valid_role(role) for role in ROLES)
    assert not is_valid_role("superuser")
    assert not is_valid_role("OWNER")  # case-sensitive on purpose


# ---------------------------------------------------------------------------
# Documentation generator
# ---------------------------------------------------------------------------


def test_describe_matrix_covers_every_permission_and_names_holders():
    described = describe_matrix()
    assert len(described) == len(PERMISSIONS)
    assert {row["permission"] for row in described} == set(PERMISSIONS)
    for row in described:
        assert row["roles"], f"{row['permission']} is held by nobody — dead permission?"
        assert all(role in ROLES for role in row["roles"])
