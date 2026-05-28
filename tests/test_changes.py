"""Tests for cross-scan change detection."""

from __future__ import annotations

import pytest

from vanguard_x.core.changes import ChangeDetector
from vanguard_x.models import (
    Asset,
    AssetType,
    ScanStatus,
)


@pytest.fixture
def detector(repository):
    return ChangeDetector(repository)


# -----------------------------------------------------------------------------
async def test_baseline_scan_emits_all_assets_as_new(repository, detector):
    scan_id = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        scan_id,
        [
            Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap"),
            Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com", source_tool="subfinder"),
        ],
    )
    await repository.mark_done(scan_id)

    diff = await detector.detect(scan_id)

    assert diff.is_baseline
    assert diff.previous_scan_id is None
    assert len(diff.new) == 2
    assert diff.removed == []
    assert diff.has_changes  # baseline has changes by definition (all new)


# -----------------------------------------------------------------------------
async def test_no_changes_between_identical_scans(repository, detector):
    assets = [
        Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap"),
        Asset(asset_type=AssetType.PORT, value="1.2.3.4:80/tcp", source_tool="nmap"),
    ]

    scan1 = await repository.create_scan(target="example.com")
    await repository.persist_assets(scan1, assets)
    await repository.mark_done(scan1)

    scan2 = await repository.create_scan(target="example.com")
    await repository.persist_assets(scan2, assets)
    await repository.mark_done(scan2)

    diff = await detector.detect(scan2)
    assert diff.previous_scan_id == scan1
    assert not diff.has_changes
    assert diff.new == []
    assert diff.removed == []


# -----------------------------------------------------------------------------
async def test_new_and_removed_assets_detected(repository, detector):
    scan1 = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        scan1,
        [
            Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap"),
            Asset(asset_type=AssetType.PORT, value="1.2.3.4:22/tcp", source_tool="nmap"),
            Asset(asset_type=AssetType.SUBDOMAIN, value="old.example.com", source_tool="subfinder"),
        ],
    )
    await repository.mark_done(scan1)

    scan2 = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        scan2,
        [
            Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap"),
            # 22 disappeared (removed), 80 is new
            Asset(asset_type=AssetType.PORT, value="1.2.3.4:80/tcp", source_tool="nmap"),
            # subdomain renamed: old removed, new added
            Asset(asset_type=AssetType.SUBDOMAIN, value="new.example.com", source_tool="subfinder"),
        ],
    )
    await repository.mark_done(scan2)

    diff = await detector.detect(scan2)

    new_keys = sorted((a.asset_type.value, a.value) for a in diff.new)
    removed_keys = sorted((a.asset_type.value, a.value) for a in diff.removed)
    assert new_keys == [
        ("port", "1.2.3.4:80/tcp"),
        ("subdomain", "new.example.com"),
    ]
    assert removed_keys == [
        ("port", "1.2.3.4:22/tcp"),
        ("subdomain", "old.example.com"),
    ]
    assert diff.total_changes == 4


# -----------------------------------------------------------------------------
async def test_only_compares_to_same_target(repository, detector):
    """A scan against another target must NOT count as 'previous' history."""
    other = await repository.create_scan(target="other.com")
    await repository.persist_assets(
        other,
        [Asset(asset_type=AssetType.HOST, value="9.9.9.9", source_tool="nmap")],
    )
    await repository.mark_done(other)

    scan1 = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        scan1,
        [Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap")],
    )
    await repository.mark_done(scan1)

    diff = await detector.detect(scan1)
    # No prior scan for example.com -> baseline.
    assert diff.is_baseline
    assert diff.previous_scan_id is None


async def test_only_compares_to_done_scans(repository, detector):
    """FAILED / SCOPE_VIOLATION runs should not be used as 'previous'."""
    failed = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        failed, [Asset(asset_type=AssetType.HOST, value="9.9.9.9", source_tool="nmap")]
    )
    await repository.mark_failed(failed, error="boom")

    scan1 = await repository.create_scan(target="example.com")
    await repository.persist_assets(
        scan1,
        [Asset(asset_type=AssetType.HOST, value="1.2.3.4", source_tool="nmap")],
    )
    await repository.mark_done(scan1)

    diff = await detector.detect(scan1)
    assert diff.is_baseline


# -----------------------------------------------------------------------------
async def test_detect_unknown_scan_raises(detector):
    with pytest.raises(LookupError):
        await detector.detect(99999)


async def test_repository_previous_completed_scan_picks_latest(repository):
    """The most recent DONE scan wins when multiple exist."""
    a = await repository.create_scan(target="example.com")
    await repository.mark_done(a)
    b = await repository.create_scan(target="example.com")
    await repository.mark_done(b)
    c = await repository.create_scan(target="example.com")
    # c not finalised yet.

    prev = await repository.previous_completed_scan(target="example.com", before_scan_id=c)
    assert prev is not None
    assert prev.id == b
    assert prev.status == ScanStatus.DONE.value
