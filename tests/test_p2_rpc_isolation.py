import pytest
from flask import Flask, Response
import json
import os
import sqlite3
from unittest.mock import patch, MagicMock

from guardian.web3sec.rpc_relay import GuardianRPCRelay, decode_raw_transaction

@pytest.fixture
def relay():
    config = {
        "web3_security": {
            "listen_port": 8546,
            "upstream_rpc": "http://mock-rpc",
            "fail_mode": "closed",
            "enforce_simulation": False
        },
        "security_policies": {
            "admin_token": "test_token"
        }
    }
    with patch("guardian.web3sec.rpc_relay.Web3"):
        with patch("guardian.web3sec.rpc_relay.SimulationEngine"):
            with patch("guardian.web3sec.rpc_relay.TransactionAnalyzer"):
                r = GuardianRPCRelay(config)
                # mock DB to be in-memory for testing
                import tempfile
                r.db_path = tempfile.mktemp(suffix=".db")
                r._init_db()
                return r

def test_rpc_relay_health(relay):
    with relay.app.test_client() as client:
        resp = client.get('/health')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"

def test_rpc_relay_stats(relay):
    with relay.app.test_client() as client:
        resp = client.get('/stats')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"

def test_management_auth_missing(relay):
    with relay.app.test_client() as client:
        resp = client.post('/rules', json={"test": True})
        assert resp.status_code == 401

def test_management_auth_invalid(relay):
    with relay.app.test_client() as client:
        resp = client.post('/rules', headers={"Authorization": "Bearer bad_token"}, json={"test": True})
        assert resp.status_code == 403

def test_management_auth_valid(relay):
    with relay.app.test_client() as client:
        resp = client.post('/rules', headers={"Authorization": "Bearer test_token"}, json={"test_rule": True})
        assert resp.status_code == 200
        
        # Verify it was saved
        get_resp = client.get('/rules')
        assert get_resp.status_code == 200
        rules = json.loads(get_resp.data)["rules"]
        assert rules["test_rule"] is True

def test_whitelist_management(relay):
    with relay.app.test_client() as client:
        # Add
        resp = client.post(
            '/whitelist', 
            headers={"Authorization": "Bearer test_token"}, 
            json={"address": "0x123", "label": "test"}
        )
        assert resp.status_code == 200
        
        # Get
        get_resp = client.get('/whitelist')
        assert get_resp.status_code == 200
        whitelist = json.loads(get_resp.data)["whitelist"]
        assert "0x123" in whitelist
        
        # Delete
        del_resp = client.delete(
            '/whitelist/0x123',
            headers={"Authorization": "Bearer test_token"}
        )
        assert del_resp.status_code == 200

def test_decode_raw_transaction_invalid_type():
    with patch("guardian.web3sec.rpc_relay.Account.recover_transaction", return_value="0x123"):
        with pytest.raises(ValueError):
            # 0x05 is not a valid type (1, 2, 3, 4, >= 0xc0)
            decode_raw_transaction("0x0500")

