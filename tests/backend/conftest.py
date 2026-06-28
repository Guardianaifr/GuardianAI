import pytest
import sys
import importlib
import os

os.environ["GUARDIAN_ADMIN_PASS"] = "guardian_default"
os.environ["GUARDIAN_JWT_SECRET"] = "guardian_jwt_dev_secret_change_me"

@pytest.fixture(autouse=True)
def sync_monkeypatch(monkeypatch):
    """
    Ensures that when tests mock variables on backend.main, 
    those mocks are propagated to the router modules and the modules are correctly reloaded.
    """
    import backend.main as backend_main
    original_setattr = monkeypatch.setattr

    def synced_setattr(*args, **kwargs):
        original_setattr(*args, **kwargs)
        if not args:
            return
        target = args[0]
        name_attr = None
        val = None
        is_backend_main = False
        if len(args) >= 3:
            name_attr = args[1]
            val = args[2]
            if target is backend_main or getattr(target, "__name__", "") == "backend.main":
                is_backend_main = True
        elif len(args) == 2:
            val = args[1]
            if isinstance(target, str) and target.startswith("backend.main."):
                name_attr = target.split(".")[-1]
                is_backend_main = True
        if is_backend_main and name_attr:
            for mod_name, mod in sys.modules.items():
                if mod_name.startswith("backend.routers."):
                    if hasattr(mod, name_attr):
                        original_setattr(mod, name_attr, val)

    monkeypatch.setattr = synced_setattr

    # 1. Provide a reliable way to reload backend.main for tests that need complete state isolation
    original_reload = importlib.reload

    def synced_reload(module):
        if module.__name__ == "backend.main":
            # 2. Clear cached modules so importlib.reload works correctly
            for k in list(sys.modules.keys()):
                if k.startswith("backend.routers.") or k == "backend.routers":
                    sys.modules.pop(k, None)
        return original_reload(module)

    importlib.reload = synced_reload
    
    yield
