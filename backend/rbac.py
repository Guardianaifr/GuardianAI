"""
Role-Based Access Control (RBAC) for GuardianAI Backend.

Defines 4 role levels with granular per-resource permissions and provides
FastAPI dependency functions for endpoint-level access gates.

Role Hierarchy:
    admin > analyst > tenant_admin > read_only

Tenant Scoping:
    - admin: Full access to all tenants
    - analyst: Read/write events across all tenants
    - tenant_admin: Full access but scoped to own tenant only
    - read_only: Read-only access scoped to own tenant
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, HTTPException, Request, status


# ---------------------------------------------------------------------------
# Role Definitions
# ---------------------------------------------------------------------------

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    TENANT_ADMIN = "tenant_admin"
    READ_ONLY = "read_only"


VALID_ROLES: Set[str] = {r.value for r in Role}

# Role hierarchy: higher number = more privileges
ROLE_HIERARCHY: Dict[str, int] = {
    "read_only": 0,
    "tenant_admin": 1,
    "analyst": 2,
    "admin": 3,
}


# ---------------------------------------------------------------------------
# Permission Matrix
# ---------------------------------------------------------------------------

class Permission(str, Enum):
    # Events
    EVENTS_READ = "events:read"
    EVENTS_WRITE = "events:write"
    EVENTS_EXPORT = "events:export"

    # Configuration
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"

    # Users
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"

    # Tenants
    TENANTS_READ = "tenants:read"
    TENANTS_WRITE = "tenants:write"

    # Compliance
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_WRITE = "compliance:write"

    # Analytics
    ANALYTICS_READ = "analytics:read"

    # Admin
    ADMIN_FULL = "admin:full"


# Which permissions each role has
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "read_only": {
        Permission.EVENTS_READ,
        Permission.COMPLIANCE_READ,
        Permission.ANALYTICS_READ,
    },
    "analyst": {
        Permission.EVENTS_READ,
        Permission.EVENTS_WRITE,
        Permission.EVENTS_EXPORT,
        Permission.COMPLIANCE_READ,
        Permission.ANALYTICS_READ,
        Permission.CONFIG_READ,
    },
    "tenant_admin": {
        Permission.EVENTS_READ,
        Permission.EVENTS_WRITE,
        Permission.EVENTS_EXPORT,
        Permission.CONFIG_READ,
        Permission.CONFIG_WRITE,
        Permission.TENANTS_READ,
        Permission.TENANTS_WRITE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_WRITE,
        Permission.ANALYTICS_READ,
    },
    "admin": {
        Permission.EVENTS_READ,
        Permission.EVENTS_WRITE,
        Permission.EVENTS_EXPORT,
        Permission.CONFIG_READ,
        Permission.CONFIG_WRITE,
        Permission.USERS_READ,
        Permission.USERS_WRITE,
        Permission.TENANTS_READ,
        Permission.TENANTS_WRITE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_WRITE,
        Permission.ANALYTICS_READ,
        Permission.ADMIN_FULL,
    },
}


# ---------------------------------------------------------------------------
# Permission Checking
# ---------------------------------------------------------------------------

def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission.

    Args:
        role: The user's role.
        permission: The required permission string.

    Returns:
        True if the role grants the permission.
    """
    role_perms = ROLE_PERMISSIONS.get(role, set())
    return permission in role_perms


def has_role_level(role: str, minimum_role: str) -> bool:
    """Check if a role meets a minimum hierarchy level.

    Args:
        role: The user's role.
        minimum_role: The minimum required role.

    Returns:
        True if the user's role is at or above the minimum.
    """
    user_level = ROLE_HIERARCHY.get(role, -1)
    required_level = ROLE_HIERARCHY.get(minimum_role, 999)
    return user_level >= required_level


def is_tenant_scoped(role: str) -> bool:
    """Check if a role is restricted to its own tenant.

    Returns:
        True for tenant_admin and read_only. False for admin and analyst.
    """
    return role in ("tenant_admin", "read_only")


def can_access_tenant(role: str, user_tenant: str, target_tenant: str) -> bool:
    """Check if a user can access data from a specific tenant.

    Args:
        role: User's role.
        user_tenant: User's assigned tenant.
        target_tenant: The tenant being accessed.

    Returns:
        True if access is allowed.
    """
    if not is_tenant_scoped(role):
        return True  # admin and analyst can see all tenants
    return user_tenant == target_tenant


# ---------------------------------------------------------------------------
# FastAPI Dependency Functions
# ---------------------------------------------------------------------------

