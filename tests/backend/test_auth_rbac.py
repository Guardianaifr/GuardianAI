"""
Tests for JWT Authentication and RBAC.

Covers:
  - Password hashing and verification
  - Token creation, verification, expiration
  - Token refresh with rotation
  - Token revocation
  - User CRUD operations
  - Role definitions and permissions
  - Tenant scoping logic
  - Role hierarchy checks
"""
import pytest
import sys
import os
import time
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.auth import (
    AuthManager,
    hash_password,
    verify_password,
    _jwt_encode,
    _jwt_decode,
    TokenPair,
    TokenPayload,
)
from backend.rbac import (
    Role,
    VALID_ROLES,
    ROLE_HIERARCHY,
    ROLE_PERMISSIONS,
    Permission,
    has_permission,
    has_role_level,
    is_tenant_scoped,
    can_access_tenant,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_auth.db")


@pytest.fixture
def auth(db_path):
    return AuthManager(db_path=db_path, secret="test-secret-key-1234", access_ttl=300, refresh_ttl=3600)


# ---------------------------------------------------------------------------
# Test: Password Hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_and_verify(self):
        pw = "MySecurePassword123!"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct-password")
        assert not verify_password("wrong-password", hashed)

    def test_different_hashes_each_time(self):
        pw = "same-password"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2  # Different salts
        assert verify_password(pw, h1)
        assert verify_password(pw, h2)

    def test_empty_password(self):
        hashed = hash_password("")
        assert verify_password("", hashed)
        assert not verify_password("not-empty", hashed)

    def test_invalid_hash_format(self):
        assert not verify_password("test", "nodoallarsign")


# ---------------------------------------------------------------------------
# Test: JWT Token Encoding/Decoding
# ---------------------------------------------------------------------------

class TestJWTTokens:
    def test_encode_decode_roundtrip(self):
        payload = {"sub": "user1", "role": "admin", "exp": time.time() + 300}
        token = _jwt_encode(payload, "secret")
        decoded = _jwt_decode(token, "secret")
        assert decoded["sub"] == "user1"
        assert decoded["role"] == "admin"

    def test_wrong_secret_fails(self):
        payload = {"sub": "user1", "exp": time.time() + 300}
        token = _jwt_encode(payload, "correct-secret")
        with pytest.raises(ValueError, match="Invalid token signature"):
            _jwt_decode(token, "wrong-secret")

    def test_expired_token_fails(self):
        payload = {"sub": "user1", "exp": time.time() - 10}
        token = _jwt_encode(payload, "secret")
        with pytest.raises(ValueError, match="Token expired"):
            _jwt_decode(token, "secret")

    def test_invalid_format_fails(self):
        with pytest.raises(ValueError, match="Invalid token format"):
            _jwt_decode("not.a.valid.token.too.many.parts", "secret")

    def test_token_has_three_parts(self):
        token = _jwt_encode({"sub": "u1", "exp": time.time() + 60}, "s")
        parts = token.split(".")
        assert len(parts) == 3


# ---------------------------------------------------------------------------
# Test: User Management
# ---------------------------------------------------------------------------

class TestUserManagement:
    def test_create_user(self, auth):
        user = auth.create_user("testuser", "password123", role="analyst")
        assert user["username"] == "testuser"
        assert user["role"] == "analyst"
        assert user["is_active"] is True

    def test_create_duplicate_fails(self, auth):
        auth.create_user("dupe", "pass1")
        with pytest.raises(ValueError, match="already exists"):
            auth.create_user("dupe", "pass2")

    def test_create_invalid_role_fails(self, auth):
        with pytest.raises(ValueError, match="Invalid role"):
            auth.create_user("baduser", "pass", role="superadmin")

    def test_authenticate_valid(self, auth):
        auth.create_user("loginuser", "mypass", role="admin")
        user = auth.authenticate("loginuser", "mypass")
        assert user is not None
        assert user["username"] == "loginuser"
        assert user["role"] == "admin"

    def test_authenticate_wrong_password(self, auth):
        auth.create_user("user2", "correct")
        user = auth.authenticate("user2", "wrong")
        assert user is None

    def test_authenticate_nonexistent_user(self, auth):
        user = auth.authenticate("ghost", "pass")
        assert user is None

    def test_get_user(self, auth):
        auth.create_user("findme", "pass", role="tenant_admin", tenant_id="acme")
        user = auth.get_user("findme")
        assert user is not None
        assert user["role"] == "tenant_admin"
        assert user["tenant_id"] == "acme"

    def test_get_nonexistent_user(self, auth):
        assert auth.get_user("nobody") is None


# ---------------------------------------------------------------------------
# Test: Token Lifecycle
# ---------------------------------------------------------------------------

class TestTokenLifecycle:
    def test_create_token_pair(self, auth):
        auth.create_user("tokenuser", "pass", role="analyst")
        user = auth.authenticate("tokenuser", "pass")
        pair = auth.create_token_pair(user)

        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type == "bearer"
        assert pair.expires_in == 300

    def test_verify_access_token(self, auth):
        auth.create_user("verifyuser", "pass", role="admin", tenant_id="corp")
        user = auth.authenticate("verifyuser", "pass")
        pair = auth.create_token_pair(user)

        payload = auth.verify_token(pair.access_token)
        assert isinstance(payload, TokenPayload)
        assert payload.role == "admin"
        assert payload.tenant_id == "corp"
        assert payload.token_type == "access"

    def test_verify_refresh_token(self, auth):
        auth.create_user("refreshuser", "pass")
        user = auth.authenticate("refreshuser", "pass")
        pair = auth.create_token_pair(user)

        payload = auth.verify_token(pair.refresh_token)
        assert payload.token_type == "refresh"

    def test_refresh_token_rotation(self, auth):
        auth.create_user("rotateuser", "pass", role="analyst")
        user = auth.authenticate("rotateuser", "pass")
        old_pair = auth.create_token_pair(user)

        new_pair = auth.refresh_tokens(old_pair.refresh_token)
        assert new_pair.access_token != old_pair.access_token
        assert new_pair.refresh_token != old_pair.refresh_token

        # Old refresh token should be revoked
        with pytest.raises(ValueError, match="revoked"):
            auth.verify_token(old_pair.refresh_token)

        # New tokens should work
        payload = auth.verify_token(new_pair.access_token)
        assert payload.role == "analyst"

    def test_refresh_with_access_token_fails(self, auth):
        auth.create_user("badrefresh", "pass")
        user = auth.authenticate("badrefresh", "pass")
        pair = auth.create_token_pair(user)

        with pytest.raises(ValueError, match="Not a refresh token"):
            auth.refresh_tokens(pair.access_token)

    def test_revoke_token(self, auth):
        auth.create_user("revokeuser", "pass")
        user = auth.authenticate("revokeuser", "pass")
        pair = auth.create_token_pair(user)

        payload = auth.verify_token(pair.access_token)
        auth.revoke_token(payload.jti)

        with pytest.raises(ValueError, match="revoked"):
            auth.verify_token(pair.access_token)

    def test_cleanup_expired(self, auth):
        auth.create_user("cleanuser", "pass")
        user = auth.authenticate("cleanuser", "pass")
        pair = auth.create_token_pair(user)
        payload = auth.verify_token(pair.access_token)
        auth.revoke_token(payload.jti)

        deleted = auth.cleanup_expired_tokens()
        # Token was just revoked, so cleanup won't delete it yet
        assert deleted == 0


# ---------------------------------------------------------------------------
# Test: RBAC Roles
# ---------------------------------------------------------------------------

class TestRBACRoles:
    def test_valid_roles(self):
        assert "admin" in VALID_ROLES
        assert "analyst" in VALID_ROLES
        assert "tenant_admin" in VALID_ROLES
        assert "read_only" in VALID_ROLES
        assert len(VALID_ROLES) == 4

    def test_role_hierarchy_order(self):
        assert ROLE_HIERARCHY["admin"] > ROLE_HIERARCHY["analyst"]
        assert ROLE_HIERARCHY["analyst"] > ROLE_HIERARCHY["tenant_admin"]
        assert ROLE_HIERARCHY["tenant_admin"] > ROLE_HIERARCHY["read_only"]


# ---------------------------------------------------------------------------
# Test: RBAC Permissions
# ---------------------------------------------------------------------------

class TestRBACPermissions:
    def test_admin_has_all_permissions(self):
        for perm in Permission:
            assert has_permission("admin", perm), f"Admin missing: {perm}"

    def test_read_only_limited(self):
        assert has_permission("read_only", Permission.EVENTS_READ)
        assert has_permission("read_only", Permission.ANALYTICS_READ)
        assert not has_permission("read_only", Permission.EVENTS_WRITE)
        assert not has_permission("read_only", Permission.CONFIG_WRITE)
        assert not has_permission("read_only", Permission.USERS_WRITE)
        assert not has_permission("read_only", Permission.ADMIN_FULL)

    def test_analyst_can_write_events(self):
        assert has_permission("analyst", Permission.EVENTS_WRITE)
        assert has_permission("analyst", Permission.EVENTS_EXPORT)
        assert not has_permission("analyst", Permission.USERS_WRITE)
        assert not has_permission("analyst", Permission.CONFIG_WRITE)

    def test_tenant_admin_can_manage_config(self):
        assert has_permission("tenant_admin", Permission.CONFIG_WRITE)
        assert has_permission("tenant_admin", Permission.TENANTS_WRITE)
        assert not has_permission("tenant_admin", Permission.USERS_WRITE)
        assert not has_permission("tenant_admin", Permission.ADMIN_FULL)

    def test_has_role_level(self):
        assert has_role_level("admin", "admin")
        assert has_role_level("admin", "read_only")
        assert has_role_level("analyst", "analyst")
        assert has_role_level("analyst", "read_only")
        assert not has_role_level("read_only", "admin")
        assert not has_role_level("tenant_admin", "analyst")

    def test_unknown_role_has_no_permissions(self):
        assert not has_permission("unknown_role", Permission.EVENTS_READ)
        assert not has_role_level("unknown_role", "read_only")


# ---------------------------------------------------------------------------
# Test: Tenant Scoping
# ---------------------------------------------------------------------------

class TestTenantScoping:
    def test_admin_sees_all_tenants(self):
        assert can_access_tenant("admin", "tenant_a", "tenant_b")
        assert not is_tenant_scoped("admin")

    def test_analyst_sees_all_tenants(self):
        assert can_access_tenant("analyst", "tenant_a", "tenant_b")
        assert not is_tenant_scoped("analyst")

    def test_tenant_admin_scoped(self):
        assert is_tenant_scoped("tenant_admin")
        assert can_access_tenant("tenant_admin", "acme", "acme")
        assert not can_access_tenant("tenant_admin", "acme", "other")

    def test_read_only_scoped(self):
        assert is_tenant_scoped("read_only")
        assert can_access_tenant("read_only", "myco", "myco")
        assert not can_access_tenant("read_only", "myco", "other")
