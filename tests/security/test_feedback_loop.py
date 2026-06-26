from pathlib import Path

from security.feedback_loop import FeedbackLoopManager


def test_feedback_loop_add_and_match(tmp_path: Path):
    mgr = FeedbackLoopManager(
        {
            "enabled": True,
            "allowlist_file": "fp_allowlist.jsonl",
            "default_ttl_seconds": 3600,
            "max_entries": 100,
        },
        tmp_path,
    )
    mgr.add_approved_entry("acme", "benign prompt", "injection", notes="reviewed safe")
    assert mgr.is_allowlisted("acme", "benign prompt", "injection") is True


def test_feedback_loop_ttl_expiry(tmp_path: Path):
    mgr = FeedbackLoopManager(
        {
            "enabled": True,
            "allowlist_file": "fp_allowlist.jsonl",
            "default_ttl_seconds": 1,
            "max_entries": 100,
        },
        tmp_path,
    )
    entry = mgr.add_approved_entry("acme", "benign prompt", "injection", ttl_seconds=1)
    assert mgr.is_allowlisted("acme", "benign prompt", "injection", now=entry.expires_at + 1) is False
