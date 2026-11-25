"""Role -> permission mapping. The server is the only place this is enforced."""

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "user": frozenset({"dashboard:read", "profile:read"}),
    "admin": frozenset({"dashboard:read", "profile:read", "reports:read", "users:read"}),
}


def permissions_for(role: str) -> frozenset[str]:
    # Unknown role -> no permissions (fail closed).
    return ROLE_PERMISSIONS.get(role, frozenset())
