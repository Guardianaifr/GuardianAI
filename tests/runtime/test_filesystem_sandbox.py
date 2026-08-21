import pytest
from flask import Flask, request, Response
from guardian.runtime.interceptor import GuardianProxy
from guardian.runtime.filesystem_sandbox import FilesystemSandbox
import json

@pytest.fixture
def mock_config(tmp_path):
    return {
        "proxy": {
            "listen_port": 8080,
            "target_url": "http://localhost:18789",
            "enabled": True,
            "enforce_auth": False
        },
        "security_policies": {
            "admin_token": "test-admin-token-a1b2c3d4e5f6"
        },
        "guardian_id": "test-guardian",
        "filesystem_sandbox": {
            "enabled": True,
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "allowed_paths": [
                {
                    "path": str(tmp_path / "allowed_read_dir"),
                    "permission": "read"
                },
                {
                    "path": str(tmp_path / "allowed_write_dir"),
                    "permission": "write"
                },
                {
                    "path": str(tmp_path / "allowed_rw_dir"),
                    "permission": "read_write"
                }
            ]
        }
    }

@pytest.fixture
def proxy(mock_config):
    proxy = GuardianProxy(mock_config)
    proxy.filesystem_sandbox = FilesystemSandbox(mock_config)
    return proxy

def test_sandbox_allows_valid_read(proxy, mock_config, tmp_path):
    allowed_dir = tmp_path / "allowed_read_dir"
    allowed_dir.mkdir(exist_ok=True)
    allowed_file = allowed_dir / "test.txt"
    allowed_file.touch()

    data = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": str(allowed_file)})
                        }
                    }
                ]
            }
        ]
    }
    
    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    assert resp is None # Allowed

def test_sandbox_blocks_invalid_read(proxy, mock_config, tmp_path):
    forbidden_dir = tmp_path / "forbidden_dir"
    forbidden_dir.mkdir(exist_ok=True)
    forbidden_file = forbidden_dir / "secret.txt"
    forbidden_file.touch()

    data = {
        "function_call": {
            "name": "read_file",
            "arguments": json.dumps({"path": str(forbidden_file)})
        }
    }
    
    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    assert resp is not None
    assert resp.status_code == 403
    assert b"Forbidden: Filesystem Sandbox blocked" in resp.data

def test_sandbox_blocks_path_traversal(proxy, mock_config, tmp_path):
    allowed_dir = tmp_path / "allowed_read_dir"
    allowed_dir.mkdir(exist_ok=True)
    
    # Try to traverse up from allowed dir
    traversal_path = str(allowed_dir / ".." / "forbidden_dir" / "secret.txt")

    data = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"file": traversal_path})
                        }
                    }
                ]
            }
        ]
    }
    
    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    assert resp is not None
    assert resp.status_code == 403
    assert b"Forbidden: Filesystem Sandbox blocked" in resp.data


def test_sandbox_blocks_write_on_read_only_path(proxy, mock_config, tmp_path):
    """
    A path configured as read-only (allowed_read_dir) must be BLOCKED when
    the tool call is write_file.  This is the exact gap that the old double-
    check logic silently passed: check_access(path, 'read') returned True,
    so the write was never evaluated.
    """
    allowed_dir = tmp_path / "allowed_read_dir"
    allowed_dir.mkdir(exist_ok=True)
    target_file = allowed_dir / "output.log"

    data = {
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {
                            "name": "write_file",   # write intent from name
                            "arguments": json.dumps({"path": str(target_file)})
                        }
                    }
                ]
            }
        ]
    }

    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    # Must be blocked: write_file against a read-only path.
    assert resp is not None, (
        "Expected 403 for write_file on read-only path, but sandbox returned None (allowed)"
    )
    assert resp.status_code == 403
    assert b"write" in resp.data  # response names the inferred operation
    assert b"Forbidden: Filesystem Sandbox blocked" in resp.data


def test_infer_operation_write_default_for_unknown(proxy, mock_config, tmp_path):
    """
    A function with no recognisable name token (e.g. 'do_thing') and no
    explicit mode/operation arg defaults to 'write' intent — the conservative
    choice.  The path here is outside all allowed dirs, so it blocks either way;
    the test also checks that the response body says 'write' (not 'read').
    """
    forbidden_dir = tmp_path / "forbidden_dir"
    forbidden_dir.mkdir(exist_ok=True)
    target_file = forbidden_dir / "data.bin"
    target_file.touch()

    data = {
        "function_call": {
            "name": "do_thing",  # no read/write token -> defaults to write
            "arguments": json.dumps({"path": str(target_file)})
        }
    }

    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    assert resp is not None
    assert resp.status_code == 403
    assert b"write" in resp.data


def test_infer_operation_read_allowed_via_name(proxy, mock_config, tmp_path):
    """
    read_file against the read-only-configured directory must be ALLOWED.
    Confirms the infer-then-check path works in the passing direction.
    """
    allowed_dir = tmp_path / "allowed_read_dir"
    allowed_dir.mkdir(exist_ok=True)
    target_file = allowed_dir / "notes.txt"
    target_file.touch()

    data = {
        "function_call": {
            "name": "read_file",
            "arguments": json.dumps({"path": str(target_file)})
        }
    }

    resp = proxy._enforce_filesystem_sandbox(data, "v1/chat/completions")
    assert resp is None, (
        "Expected None (allowed) for read_file on read-only path, got a block"
    )
