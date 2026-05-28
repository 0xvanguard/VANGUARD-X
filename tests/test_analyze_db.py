"""Tests for analysis report database operations."""

from __future__ import annotations

from datetime import UTC, datetime

from vanguard_x.db.database import ScanRepository
from vanguard_x.models import (
    AnalysisReport,
    AttackPath,
    Effort,
    RemediationItem,
    Severity,
    TriageResult,
    TriageVerdict,
)


def _make_report(target: str = "example.com") -> AnalysisReport:
    """Create a valid AnalysisReport for testing."""
    return AnalysisReport(
        target=target,
        generated_at=datetime.now(UTC),
        findings_analyzed=5,
        triage=[
            TriageResult(
                finding_id="f1",
                verdict=TriageVerdict.TRUE_POSITIVE,
                confidence=90,
                reasoning="Confirmed vulnerability.",
            ),
            TriageResult(
                finding_id="f2",
                verdict=TriageVerdict.FALSE_POSITIVE,
                confidence=80,
                reasoning="Not exploitable in context.",
            ),
        ],
        attack_paths=[
            AttackPath(
                id="ap-1",
                title="SQLi to RCE",
                steps=["Inject SQL", "Extract creds", "Login as admin"],
                severity=Severity.CRITICAL,
                exploitability_score=0.85,
            )
        ],
        executive_summary="Target has critical vulnerabilities requiring immediate action.",
        remediation_plan=[
            RemediationItem(
                priority=1,
                title="Fix SQL Injection",
                description="Use parameterized queries.",
                effort=Effort.MEDIUM,
                affected_findings=["f1"],
            )
        ],
    )


async def test_save_analysis_report(repository: ScanRepository) -> None:
    report = _make_report()
    run_id = await repository.save_analysis_report(report)
    assert isinstance(run_id, str)
    assert len(run_id) == 16


async def test_get_analysis_report(repository: ScanRepository) -> None:
    report = _make_report()
    run_id = await repository.save_analysis_report(report)

    retrieved = await repository.get_analysis_report("example.com", run_id)
    assert retrieved is not None
    assert retrieved.target == "example.com"
    assert retrieved.findings_analyzed == 5
    assert len(retrieved.triage) == 2
    assert retrieved.triage[0].verdict == TriageVerdict.TRUE_POSITIVE
    assert len(retrieved.attack_paths) == 1
    assert retrieved.executive_summary == report.executive_summary


async def test_get_nonexistent_report(repository: ScanRepository) -> None:
    result = await repository.get_analysis_report("no-target.com", "bogus-run-id")
    assert result is None


async def test_list_analysis_reports_ordering(repository: ScanRepository) -> None:
    report1 = _make_report()
    report2 = _make_report()

    run_id1 = await repository.save_analysis_report(report1)
    run_id2 = await repository.save_analysis_report(report2)

    reports = await repository.list_analysis_reports("example.com")
    assert len(reports) == 2
    # Newest first
    assert reports[0][0] == run_id2
    assert reports[1][0] == run_id1


async def test_list_analysis_reports_empty(repository: ScanRepository) -> None:
    reports = await repository.list_analysis_reports("nonexistent.com")
    assert reports == []


async def test_save_with_scan_id(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="analyze")
    report = _make_report()
    run_id = await repository.save_analysis_report(report, scan_id=scan_id)
    assert isinstance(run_id, str)

    # Verify retrieval still works
    retrieved = await repository.get_analysis_report("example.com", run_id)
    assert retrieved is not None


async def test_report_json_roundtrip(repository: ScanRepository) -> None:
    report = _make_report()
    run_id = await repository.save_analysis_report(report)
    retrieved = await repository.get_analysis_report("example.com", run_id)

    assert retrieved is not None
    # Verify nested fields survive
    assert retrieved.triage[0].finding_id == "f1"
    assert retrieved.triage[0].confidence == 90
    assert retrieved.attack_paths[0].steps == ["Inject SQL", "Extract creds", "Login as admin"]
    assert retrieved.attack_paths[0].exploitability_score == 0.85
    assert retrieved.remediation_plan[0].effort == Effort.MEDIUM
    assert retrieved.remediation_plan[0].affected_findings == ["f1"]


async def test_multiple_targets(repository: ScanRepository) -> None:
    report_a = _make_report("target-a.com")
    report_b = _make_report("target-b.com")

    await repository.save_analysis_report(report_a)
    await repository.save_analysis_report(report_b)

    reports_a = await repository.list_analysis_reports("target-a.com")
    reports_b = await repository.list_analysis_reports("target-b.com")

    assert len(reports_a) == 1
    assert len(reports_b) == 1
