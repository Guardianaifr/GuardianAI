import json
import pytest
from pathlib import Path
from guardian.audit.scheduler import AuditScheduler, ScanSchedule, ScanResult


def test_scan_schedule_serialization():
    sched = ScanSchedule(
        schedule_id="sched-1",
        target_uri="https://api.example.com/v1",
        target_name="Example API",
        interval_seconds=3600,
        scan_mode="DEEP",
        webhook_url="https://hooks.example.com/sec",
        enabled=True,
    )
    d = sched.to_dict()
    assert d["schedule_id"] == "sched-1"
    assert d["target_uri"] == "https://api.example.com/v1"
    assert d["target_name"] == "Example API"
    assert d["interval_seconds"] == 3600
    assert d["scan_mode"] == "DEEP"
    assert d["webhook_url"] == "https://hooks.example.com/sec"

    recovered = ScanSchedule.from_dict(d)
    assert recovered.schedule_id == "sched-1"
    assert recovered.target_name == "Example API"
    assert recovered.interval_seconds == 3600


def test_scan_result_serialization():
    res = ScanResult(
        schedule_id="sched-1",
        target_uri="https://api.example.com/v1",
        score=95.5,
        grade="A+",
        block_rate=98.2,
        total_vectors=100,
        blocked_count=98,
        timestamp="2026-09-22T00:00:00Z",
    )
    d = res.to_dict()
    assert d["score"] == 95.5
    assert d["grade"] == "A+"
    assert d["blocked_count"] == 98


def test_audit_scheduler_crud_and_history(tmp_path):
    history_file = tmp_path / "scan_history.json"
    scheduler = AuditScheduler(history_file=str(history_file))

    sched1 = ScanSchedule("s1", "https://api1.test", "API 1")
    sched2 = ScanSchedule("s2", "https://api2.test", "API 2")

    scheduler.add_schedule(sched1)
    scheduler.add_schedule(sched2)

    schedules = scheduler.get_schedules()
    assert len(schedules) == 2
    assert {s["schedule_id"] for s in schedules} == {"s1", "s2"}

    assert scheduler.remove_schedule("s1") is True
    assert scheduler.remove_schedule("s1") is False
    assert len(scheduler.get_schedules()) == 1


def test_audit_scheduler_execution_and_regression(tmp_path):
    history_file = tmp_path / "scan_history.json"

    scores = [95.0, 80.0]

    def mock_scan(schedule: ScanSchedule) -> ScanResult:
        score = scores.pop(0)
        return ScanResult(
            schedule_id=schedule.schedule_id,
            target_uri=schedule.target_uri,
            score=score,
            grade="A" if score > 90 else "B",
            block_rate=score,
            total_vectors=50,
            blocked_count=int(50 * (score / 100)),
            timestamp="2026-09-22T10:00:00Z",
        )

    scheduler = AuditScheduler(scan_callback=mock_scan, history_file=str(history_file))
    sched = ScanSchedule("s1", "https://api.test", "TestAPI", interval_seconds=10)
    scheduler.add_schedule(sched)

    # First run
    scheduler._execute_scan(sched)
    assert sched.run_count == 1
    assert sched.last_score == 95.0
    history = scheduler.get_history()
    assert len(history) == 1
    assert history[0]["regression"] is False

    # Second run (score drops -> regression detected)
    scheduler._execute_scan(sched)
    assert sched.run_count == 2
    assert sched.last_score == 80.0
    history = scheduler.get_history()
    assert len(history) == 2
    assert history[1]["regression"] is True

    # Check persistence on disk
    assert history_file.exists()
    saved = json.loads(history_file.read_text(encoding="utf-8"))
    assert len(saved) == 2
