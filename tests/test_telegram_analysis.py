"""Tests for TelegramNotifier.send_analysis_summary."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from vanguard_x.models import (
    AnalysisReport,
    AttackPath,
    Effort,
    RemediationItem,
    Severity,
    TriageResult,
    TriageVerdict,
)
from vanguard_x.notifications.telegram import TelegramNotifier


def _make_report(*, with_attack_paths: bool = True) -> AnalysisReport:
    """Create a valid AnalysisReport for testing."""
    attack_paths = []
    if with_attack_paths:
        attack_paths = [
            AttackPath(
                id="ap-1",
                title="SQLi to RCE",
                steps=["Inject SQL", "Extract creds", "Gain shell"],
                severity=Severity.CRITICAL,
                exploitability_score=0.9,
            ),
            AttackPath(
                id="ap-2",
                title="XSS to session hijack",
                steps=["Find XSS", "Steal cookie"],
                severity=Severity.HIGH,
                exploitability_score=0.6,
            ),
        ]

    return AnalysisReport(
        target="example.com",
        generated_at=datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC),
        findings_analyzed=10,
        triage=[
            TriageResult(
                finding_id="f1",
                verdict=TriageVerdict.TRUE_POSITIVE,
                confidence=95,
                reasoning="Confirmed SQLi.",
            )
        ],
        attack_paths=attack_paths,
        executive_summary="The target has critical vulnerabilities requiring immediate action.",
        remediation_plan=[
            RemediationItem(
                priority=1,
                title="Fix SQLi",
                description="Use parameterized queries.",
                effort=Effort.HIGH,
                affected_findings=["f1"],
            )
        ],
    )


async def test_send_analysis_summary_renders() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)

    report = _make_report()
    ok = await notifier.send_analysis_summary(report)
    assert ok is True

    body = captured["body"]
    assert "ANALYSIS REPORT" in body
    assert "example.com" in body
    assert "Executive Summary" in body
    assert "critical vulnerabilities" in body
    assert "Top Attack Path" in body
    assert "SQLi to RCE" in body
    await notifier.aclose()


async def test_send_analysis_summary_no_attack_paths() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)

    report = _make_report(with_attack_paths=False)
    ok = await notifier.send_analysis_summary(report)
    assert ok is True

    body = captured["body"]
    assert "ANALYSIS REPORT" in body
    assert "Executive Summary" in body
    # Should NOT have attack path section
    assert "Top Attack Path" not in body
    await notifier.aclose()


async def test_send_analysis_summary_disabled() -> None:
    notifier = TelegramNotifier(bot_token=None, chat_id=None)
    report = _make_report()
    ok = await notifier.send_analysis_summary(report)
    assert ok is False
    await notifier.aclose()


async def test_send_analysis_summary_network_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)

    report = _make_report()
    ok = await notifier.send_analysis_summary(report)
    assert ok is False
    await notifier.aclose()
