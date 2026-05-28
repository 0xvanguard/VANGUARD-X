"""Smoke tests for Pydantic value objects."""

from __future__ import annotations

from datetime import UTC, datetime

from vanguard_x.models import (
    Asset,
    AssetType,
    Finding,
    Severity,
    ToolRunResult,
)


def test_asset_dedupe_key_normalises_value():
    a = Asset(asset_type=AssetType.HOST, value="Example.COM", source_tool="nmap")
    b = Asset(asset_type=AssetType.HOST, value="example.com", source_tool="harvester")
    assert a.dedupe_key() == b.dedupe_key()


def test_finding_default_status_and_confidence():
    f = Finding(
        severity=Severity.HIGH,
        title="Outdated nginx",
        source_tool="nmap",
    )
    assert f.confidence == 100
    assert f.status.value == "open"


def test_tool_run_result_duration_and_success():
    started = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    completed = datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC)
    r = ToolRunResult(
        tool="nmap",
        target="example.com",
        started_at=started,
        completed_at=completed,
        return_code=0,
    )
    assert r.duration_seconds == 5.0
    assert r.succeeded
