from security.tenant_sensitivity import TenantSensitivityManager


def test_tenant_sensitivity_disabled_uses_fallback():
    mgr = TenantSensitivityManager({"enabled": False})
    profile = mgr.resolve("acme", "balanced", True)
    assert profile.security_mode == "balanced"
    assert profile.show_block_reason is True


def test_tenant_sensitivity_per_tenant_override():
    mgr = TenantSensitivityManager(
        {
            "enabled": True,
            "tenant_modes": {
                "acme": {"security_mode": "strict", "show_block_reason": False}
            },
        }
    )
    profile = mgr.resolve("acme", "balanced", True)
    assert profile.security_mode == "strict"
    assert profile.show_block_reason is False
