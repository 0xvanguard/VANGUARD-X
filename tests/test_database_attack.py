"""Tests for new ScanRepository methods (attack support)."""

from __future__ import annotations

from vanguard_x.models import (
    Asset,
    AssetType,
    Finding,
    Severity,
)


async def test_save_attack_result(repository):
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    findings = [
        Finding(severity=Severity.CRITICAL, title="RCE", source_tool="nuclei"),
        Finding(severity=Severity.HIGH, title="XSS", source_tool="nuclei"),
    ]
    assets = [
        Asset(asset_type=AssetType.URL, value="http://example.com/admin", source_tool="gobuster"),
        Asset(asset_type=AssetType.URL, value="http://example.com/login", source_tool="gobuster"),
    ]

    f_count, a_count = await repository.save_attack_result(scan_id, findings, assets)
    assert f_count == 2
    assert a_count == 2


async def test_get_attack_results(repository):
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    findings = [
        Finding(severity=Severity.HIGH, title="SQLi", source_tool="nuclei"),
    ]
    assets = [
        Asset(asset_type=AssetType.URL, value="http://example.com/api", source_tool="gobuster"),
    ]
    await repository.save_attack_result(scan_id, findings, assets)

    result_findings, result_assets = await repository.get_attack_results(scan_id)
    assert len(result_findings) == 1
    assert len(result_assets) == 1
    assert result_findings[0].title == "SQLi"
    assert result_assets[0].value == "http://example.com/api"


async def test_get_findings_by_severity(repository):
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    findings = [
        Finding(severity=Severity.CRITICAL, title="RCE", source_tool="nuclei"),
        Finding(severity=Severity.HIGH, title="XSS", source_tool="nuclei"),
        Finding(severity=Severity.LOW, title="Info leak", source_tool="nuclei"),
        Finding(severity=Severity.CRITICAL, title="SSRF", source_tool="nuclei"),
    ]
    await repository.persist_findings(scan_id, findings)

    critical = await repository.get_findings_by_severity(Severity.CRITICAL)
    assert len(critical) == 2
    titles = {f.title for f in critical}
    assert "RCE" in titles
    assert "SSRF" in titles

    high = await repository.get_findings_by_severity(Severity.HIGH)
    assert len(high) == 1
    assert high[0].title == "XSS"

    medium = await repository.get_findings_by_severity(Severity.MEDIUM)
    assert len(medium) == 0


async def test_get_findings_by_severity_limit(repository):
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    findings = [
        Finding(severity=Severity.HIGH, title=f"F{i}", source_tool="nuclei") for i in range(10)
    ]
    await repository.persist_findings(scan_id, findings)

    limited = await repository.get_findings_by_severity(Severity.HIGH, limit=3)
    assert len(limited) == 3


async def test_get_pipeline_results(repository):
    # Create multiple scans for the same target
    scan_id1 = await repository.create_scan(target="example.com", agent="recon")
    await repository.mark_done(scan_id1)
    scan_id2 = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_done(scan_id2)
    # Different target - should not appear
    scan_id3 = await repository.create_scan(target="other.com", agent="recon")
    await repository.mark_done(scan_id3)

    summaries = await repository.get_pipeline_results("example.com")
    assert len(summaries) == 2
    # Ordered by most recent first
    assert summaries[0].scan_id == scan_id2
    assert summaries[1].scan_id == scan_id1
