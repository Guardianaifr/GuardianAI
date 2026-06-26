import pytest
import sys
import importlib

@pytest.fixture(autouse=True)
def sync_monkeypatch(monkeypatch):
    """
    Ensures that when tests mock variables on backend.main, 
    those mocks are propagated to the router modules and the modules are correctly reloaded.
    """
    import backend.main as backend_main
    original_setattr = monkeypatch.setattr

    def synced_setattr(target, name, value, *args, **kwargs):
        original_setattr(target, name, value, *args, **kwargs)
        if target is backend_main or getattr(target, "__name__", "") == "backend.main":
            for mod_name, mod in sys.modules.items():
                if mod_name.startswith("backend.routers."):
                    if hasattr(mod, name):
                        setattr(mod, name, value)

    monkeypatch.setattr = synced_setattr

    # 1. Provide a reliable way to reload backend.main for tests that need complete state isolation
    original_reload = importlib.reload

    def synced_reload(module):
        if module.__name__ == "backend.main":
            # 2. Clear cached modules so importlib.reload works correctly
            for k in list(sys.modules.keys()):
                if k.startswith("backend.routers.") or k == "backend.routers":
                    sys.modules.pop(k, None)
            sys.modules.pop("backend.main", None)
        return original_reload(module)

    importlib.reload = synced_reload
    
    yield
