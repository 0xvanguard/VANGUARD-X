"""Tests for the SQLite-backed scan repository."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vanguard_x.models import (
    Asset,
    AssetType,
    Finding,
    ScanStatus,
    Severity,
)


async def test_create_scan_returns_id(repository):
    scan_id = await repository.create_scan(target="example.com")
    assert scan_id > 0


async def test_lifecycle_pending_running_done(repository):
    scan_id = await repository.create_scan(target="example.com")
    await repository.mark_running(scan_id)
    await repository.mark_done(scan_id)

    summary = await repository.scan_summary(scan_id)
    assert summary.status is ScanStatus.DONE
    assert summary.completed_at is not None


async def test_failed_scan_records_error(repository):
    scan_id = await repository.create_scan(target="example.com")
    await repository.mark_failed(scan_id, error="boom")
    summary = await repository.scan_summary(scan_id)
    assert summary.status is ScanStatus.FAILED
    assert summary.error == "boom"


async def test_scope_violation_status(repository):
    scan_id = await repository.create_scan(target="example.com")
    await repository.mark_scope_violation(scan_id, error="not authorised")
    summary = await repository.scan_summary(scan_id)
    assert summary.status is ScanStatus.SCOPE_VIOLATION


async def test_status_helpers_raise_on_unknown_id(repository):
    with pytest.raises(LookupError):
        await repository.mark_running(99999)


# -----------------------------------------------------------------------------
async def test_persist_assets_dedupes(repository):
    scan_id = await repository.create_scan(target="example.com")

    assets = [
        Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap"),
        Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="harvester"),
        Asset(asset_type=AssetType.HOST, value="1.2.3.5", source_tool="nmap"),
        Asset(asset_type=AssetType.PORT, value="1.2.3.4:80/tcp", source_tool="nmap"),
    ]
    written = await repository.persist_assets(scan_id, assets)
    assert written == 3

    rows = await repository.list_assets(scan_id)
    values = sorted((r.asset_type, r.value) for r in rows)
    assert values == [
        ("host", "1.2.3.4"),
        ("host", "1.2.3.5"),
        ("port", "1.2.3.4:80/tcp"),
    ]


async def test_persist_assets_empty_returns_zero(repository):
    scan_id = await repository.create_scan(target="example.com")
    written = await repository.persist_assets(scan_id, [])
    assert written == 0


# -----------------------------------------------------------------------------
async def test_persist_findings_and_summary_breakdown(repository):
    scan_id = await repository.create_scan(target="example.com")
    await repository.persist_findings(
        scan_id,
        [
            Finding(severity=Severity.CRITICAL, title="X", source_tool="nuclei"),
            Finding(severity=Severity.HIGH, title="Y", source_tool="nuclei"),
            Finding(severity=Severity.HIGH, title="Z", source_tool="nuclei"),
            Finding(severity=Severity.INFO, title="W", source_tool="nuclei"),
        ],
    )
    summary = await repository.scan_summary(scan_id)
    assert summary.finding_count == 4
    assert summary.findings_by_severity[Severity.CRITICAL] == 1
    assert summary.findings_by_severity[Severity.HIGH] == 2
    assert summary.findings_by_severity[Severity.INFO] == 1


async def test_summary_for_unknown_scan_raises(repository):
    with pytest.raises(LookupError):
        await repository.scan_summary(424242)


# -----------------------------------------------------------------------------
async def test_started_at_is_timezone_aware(repository):
    scan_id = await repository.create_scan(target="example.com")
    summary = await repository.scan_summary(scan_id)
    assert summary.started_at.tzinfo is not None
    # Ensure UTC, not naive local
    offset = summary.started_at.utcoffset()
    assert offset is not None
    assert offset.total_seconds() == 0
    _ = datetime.now(UTC)  # silence import
