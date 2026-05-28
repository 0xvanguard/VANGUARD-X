"""Tests for the analyze and report CLI commands."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from typer.testing import CliRunner

from vanguard_x.__main__ import app
from vanguard_x.models import (
    AnalysisReport,
    AttackPath,
    Effort,
    RemediationItem,
    Severity,
    TriageResult,
    TriageVerdict,
)

runner = CliRunner()


def _close_coro_and_return(value):  # type: ignore[no-untyped-def]
    """Return a side_effect for asyncio.run that closes the coroutine and returns value."""

    def _side_effect(coro):  # type: ignore[no-untyped-def]
        coro.close()
        return value

    return _side_effect


def _make_report() -> AnalysisReport:
    return AnalysisReport(
        target="example.com",
        generated_at=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
        findings_analyzed=3,
        triage=[
            TriageResult(
                finding_id="f1",
                verdict=TriageVerdict.TRUE_POSITIVE,
                confidence=90,
                reasoning="Confirmed.",
            )
        ],
        attack_paths=[
            AttackPath(
                id="ap-1",
                title="SQLi Chain",
                steps=["step1", "step2"],
                severity=Severity.HIGH,
                exploitability_score=0.75,
            )
        ],
        executive_summary="Critical issues found.",
        remediation_plan=[
            RemediationItem(
                priority=1,
                title="Fix SQLi",
                description="Parameterize queries.",
                effort=Effort.MEDIUM,
                affected_findings=["f1"],
            )
        ],
    )


def test_analyze_missing_api_key() -> None:
    with patch("vanguard_x.__main__.get_settings") as mock_settings:
        settings = mock_settings.return_value
        settings.anthropic_api_key = None
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["analyze", "--target", "example.com"])
    assert result.exit_code == 1
    assert "ANTHROPIC_API_KEY" in result.output


def test_analyze_json_output() -> None:
    report = _make_report()
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch("vanguard_x.__main__.asyncio.run", side_effect=_close_coro_and_return(report)),
    ):
        settings = mock_settings.return_value
        settings.anthropic_api_key = "test-key"
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["analyze", "--target", "example.com", "--json"])
    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "executive_summary" in result.output


def test_analyze_table_output() -> None:
    report = _make_report()
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch("vanguard_x.__main__.asyncio.run", side_effect=_close_coro_and_return(report)),
    ):
        settings = mock_settings.return_value
        settings.anthropic_api_key = "test-key"
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["analyze", "--target", "example.com"])
    assert result.exit_code == 0
    assert "Analysis Report" in result.output


def test_report_markdown() -> None:
    md = "# Security Report: example.com\n\n## Executive Summary\n\nCritical issues found."
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch("vanguard_x.__main__.asyncio.run", side_effect=_close_coro_and_return(md)),
    ):
        settings = mock_settings.return_value
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["report", "--target", "example.com"])
    assert result.exit_code == 0
    assert "Security Report" in result.output


def test_report_html() -> None:
    html_output = (
        "<!DOCTYPE html>\n<html>\n<head><title>Security Report: example.com</title></head>\n"
        "<body>\n<pre>\n# Security Report\n</pre>\n</body>\n</html>"
    )
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch("vanguard_x.__main__.asyncio.run", side_effect=_close_coro_and_return(html_output)),
    ):
        settings = mock_settings.return_value
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["report", "--target", "example.com", "--format", "html"])
    assert result.exit_code == 0
    assert "<!DOCTYPE html>" in result.output


def test_report_no_data() -> None:
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch("vanguard_x.__main__.asyncio.run", side_effect=_close_coro_and_return(None)),
    ):
        settings = mock_settings.return_value
        settings.log_level = "INFO"
        settings.environment = "development"
        result = runner.invoke(app, ["report", "--target", "example.com"])
    assert result.exit_code == 0
    assert "No data found" in result.output


def test_pipeline_with_analyze_flag() -> None:
    """Verify the --analyze flag exists and is accepted by the pipeline command."""
    from vanguard_x.models import ScanStatus, ScanSummary

    summary = ScanSummary(
        scan_id=1,
        target="example.com",
        scope_label="external",
        status=ScanStatus.DONE,
        started_at=datetime(2024, 1, 1, tzinfo=UTC),
        asset_count=3,
        finding_count=5,
        findings_by_severity={},
    )
    from vanguard_x.pipeline import PipelineResult

    pipeline_result = PipelineResult(
        recon_summary=summary,
        attack_summary=summary,
        total_findings=5,
        critical_count=1,
    )
    with (
        patch("vanguard_x.__main__.get_settings") as mock_settings,
        patch(
            "vanguard_x.__main__.asyncio.run",
            side_effect=_close_coro_and_return(pipeline_result),
        ),
    ):
        settings = mock_settings.return_value
        settings.log_level = "INFO"
        settings.environment = "development"
        settings.authorized_targets = "example.com"
        result = runner.invoke(app, ["pipeline", "--target", "example.com", "--analyze"])
    assert result.exit_code == 0
    assert "Pipeline complete" in result.output


def test_analyze_help() -> None:
    result = runner.invoke(app, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output
    assert "--json" in result.output
    assert "--run-id" in result.output
