"""Tests for the AnalyzeAgent."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vanguard_x.agents.analyze import _BATCH_SIZE, AnalyzeAgent
from vanguard_x.db.database import ScanRepository
from vanguard_x.db.schema import FindingRow
from vanguard_x.models import (
    AnalysisReport,
    Severity,
    TriageVerdict,
)
from vanguard_x.notifications.telegram import TelegramNotifier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_anthropic_response(tool_name: str, tool_input: dict) -> MagicMock:
    """Create a mock response matching anthropic.types.Message structure."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = tool_name
    tool_block.input = tool_input

    response = MagicMock()
    response.content = [tool_block]
    return response


def _full_report_data(findings_count: int = 3) -> dict:
    """Return valid tool_use data for a full analysis report."""
    return {
        "findings_analyzed": findings_count,
        "triage": [
            {
                "finding_id": f"f{i}",
                "verdict": "true_positive",
                "confidence": 85,
                "reasoning": f"Finding {i} is valid.",
            }
            for i in range(1, findings_count + 1)
        ],
        "attack_paths": [
            {
                "id": "ap-1",
                "title": "SQL Injection to RCE",
                "steps": ["Find SQLi", "Extract credentials", "Gain shell"],
                "severity": "high",
                "exploitability_score": 0.8,
            }
        ],
        "executive_summary": "The target has critical vulnerabilities.",
        "remediation_plan": [
            {
                "priority": 1,
                "title": "Patch SQLi",
                "description": "Parameterize all queries.",
                "effort": "medium",
                "affected_findings": ["f1"],
            }
        ],
    }


def _make_finding_row(i: int) -> FindingRow:
    """Create a minimal FindingRow instance for testing."""
    row = FindingRow(
        id=i,
        scan_id=1,
        severity=Severity.HIGH.value,
        title=f"Finding {i}",
        description=f"Description for finding {i}",
        source_tool="nuclei",
        cve=None,
        evidence={},
        status="open",
        confidence=90,
        discovered_at=datetime.now(UTC),
    )
    return row


def _make_agent(repository: ScanRepository) -> AnalyzeAgent:
    """Create an AnalyzeAgent with a disabled notifier."""
    notifier = TelegramNotifier(bot_token=None, chat_id=None)
    return AnalyzeAgent(
        repository=repository,
        notifier=notifier,
        api_key="test-key",
        model="claude-test",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_agent_instantiation(repository: ScanRepository) -> None:
    agent = _make_agent(repository)
    assert agent.AGENT_NAME == "analyze"
    assert agent._model == "claude-test"


async def test_run_with_no_findings(repository: ScanRepository) -> None:
    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response(
        "produce_analysis_report",
        {
            "findings_analyzed": 0,
            "triage": [],
            "attack_paths": [],
            "executive_summary": "No findings to analyze.",
            "remediation_plan": [],
        },
    )
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    report = await agent.run("example.com")
    assert report.findings_analyzed == 0
    assert report.triage == []
    assert report.executive_summary == "No findings to analyze."


async def test_run_single_batch(repository: ScanRepository) -> None:
    # Create a scan with some findings
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [
        Finding(
            severity=Severity.HIGH,
            title=f"Vuln {i}",
            source_tool="nuclei",
            description=f"Desc {i}",
        )
        for i in range(3)
    ]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response("produce_analysis_report", _full_report_data(3))
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    report = await agent.run("example.com")
    assert report.target == "example.com"
    assert report.findings_analyzed == 3
    assert len(report.triage) == 3
    assert len(report.attack_paths) == 1


async def test_run_chunked(repository: ScanRepository) -> None:
    # Create scan with 75 findings
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [
        Finding(
            severity=Severity.MEDIUM,
            title=f"Vuln {i}",
            source_tool="nuclei",
            description=f"Desc {i}",
        )
        for i in range(75)
    ]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)

    # First 2 calls are triage batches, 3rd is synthesis
    triage_batch_response = _mock_anthropic_response(
        "produce_triage_batch",
        {
            "triage": [
                {
                    "finding_id": f"f{i}",
                    "verdict": "true_positive",
                    "confidence": 80,
                    "reasoning": "Valid finding.",
                }
                for i in range(25)
            ]
        },
    )
    final_response = _mock_anthropic_response(
        "produce_analysis_report",
        {
            "attack_paths": [
                {
                    "id": "ap-1",
                    "title": "Chain exploit",
                    "steps": ["step1", "step2"],
                    "severity": "critical",
                    "exploitability_score": 0.9,
                }
            ],
            "executive_summary": "Serious issues found.",
            "remediation_plan": [],
        },
    )

    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(
        side_effect=[triage_batch_response, triage_batch_response, final_response]
    )

    report = await agent.run("example.com")
    assert report.findings_analyzed == 75
    assert len(report.attack_paths) == 1
    assert report.attack_paths[0].severity == Severity.CRITICAL


async def test_chunking_calls_correct_number_of_times(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [
        Finding(
            severity=Severity.LOW,
            title=f"Vuln {i}",
            source_tool="nuclei",
            description=f"Desc {i}",
        )
        for i in range(75)
    ]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)

    triage_response = _mock_anthropic_response("produce_triage_batch", {"triage": []})
    final_response = _mock_anthropic_response(
        "produce_analysis_report",
        {
            "attack_paths": [],
            "executive_summary": "Summary.",
            "remediation_plan": [],
        },
    )

    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(
        side_effect=[triage_response, triage_response, final_response]
    )

    await agent.run("example.com")
    # 2 triage batches (50 + 25) + 1 final synthesis = 3 calls
    assert agent._client.messages.create.call_count == 3


async def test_api_failure_marks_scan_failed(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))

    with pytest.raises(RuntimeError, match="API down"):
        await agent.run("example.com", scan_id=scan_id)


async def test_report_persisted_to_db(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [Finding(severity=Severity.HIGH, title="V1", source_tool="nuclei", description="D1")]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response("produce_analysis_report", _full_report_data(1))
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    await agent.run("example.com")

    # Verify persisted
    reports = await repository.list_analysis_reports("example.com")
    assert len(reports) == 1


async def test_notification_sent(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [Finding(severity=Severity.HIGH, title="V1", source_tool="nuclei", description="D1")]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    notifier = TelegramNotifier(bot_token=None, chat_id=None)
    agent = AnalyzeAgent(repository=repository, notifier=notifier, api_key="k", model="m")
    mock_response = _mock_anthropic_response("produce_analysis_report", _full_report_data(1))
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    with patch.object(notifier, "send_analysis_summary", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = True
        await agent.run("example.com")
        mock_notify.assert_called_once()


async def test_extract_tool_use_missing_block() -> None:
    response = MagicMock()
    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = "hello"
    response.content = [text_block]

    with pytest.raises(ValueError, match="No tool_use block"):
        AnalyzeAgent._extract_tool_use(response, "produce_analysis_report")


async def test_build_report_structure() -> None:
    data = _full_report_data(2)
    report = AnalyzeAgent._build_report("target.com", data, 2)
    assert isinstance(report, AnalysisReport)
    assert report.target == "target.com"
    assert report.findings_analyzed == 2
    assert len(report.triage) == 2
    assert report.triage[0].verdict == TriageVerdict.TRUE_POSITIVE
    assert len(report.attack_paths) == 1
    assert report.attack_paths[0].severity == Severity.HIGH


async def test_format_findings() -> None:
    findings = [_make_finding_row(1), _make_finding_row(2)]
    text = AnalyzeAgent._format_findings(findings)
    assert "Total findings to analyze: 2" in text
    assert "Finding #1" in text
    assert "Finding #2" in text
    assert "nuclei" in text


async def test_finding_lookup_by_scan_id(repository: ScanRepository) -> None:
    scan_id = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id)
    from vanguard_x.models import Finding

    findings = [
        Finding(severity=Severity.HIGH, title="Specific", source_tool="nuclei", description="D")
    ]
    await repository.persist_findings(scan_id, findings)
    await repository.mark_done(scan_id)

    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response("produce_analysis_report", _full_report_data(1))
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    report = await agent.run("example.com", scan_id=scan_id)
    assert report.findings_analyzed == 1


async def test_finding_lookup_latest_scan(repository: ScanRepository) -> None:
    # Create two scans, verify latest is used
    scan_id1 = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id1)
    from vanguard_x.models import Finding

    await repository.persist_findings(
        scan_id1, [Finding(severity=Severity.LOW, title="Old", source_tool="n", description="d")]
    )
    await repository.mark_done(scan_id1)

    scan_id2 = await repository.create_scan(target="example.com", agent="attack")
    await repository.mark_running(scan_id2)
    await repository.persist_findings(
        scan_id2,
        [
            Finding(severity=Severity.HIGH, title="New1", source_tool="n", description="d"),
            Finding(severity=Severity.HIGH, title="New2", source_tool="n", description="d"),
        ],
    )
    await repository.mark_done(scan_id2)

    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response("produce_analysis_report", _full_report_data(2))
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    report = await agent.run("example.com")
    # Should use latest scan (scan_id2) with 2 findings
    assert report.findings_analyzed == 2


async def test_finding_lookup_no_scan_exists(repository: ScanRepository) -> None:
    agent = _make_agent(repository)
    mock_response = _mock_anthropic_response(
        "produce_analysis_report",
        {
            "findings_analyzed": 0,
            "triage": [],
            "attack_paths": [],
            "executive_summary": "No data.",
            "remediation_plan": [],
        },
    )
    agent._client = MagicMock()
    agent._client.messages = MagicMock()
    agent._client.messages.create = AsyncMock(return_value=mock_response)

    report = await agent.run("nonexistent.com")
    assert report.findings_analyzed == 0


async def test_batch_size_constant() -> None:
    assert _BATCH_SIZE == 50
