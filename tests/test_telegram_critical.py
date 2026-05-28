"""Tests for TelegramNotifier.send_critical_alert."""

from __future__ import annotations

import httpx

from vanguard_x.models import Finding, Severity
from vanguard_x.notifications.telegram import TelegramNotifier


def _mock_notifier(*, enabled: bool = True) -> tuple[TelegramNotifier, list[httpx.Request]]:
    """Return a notifier and a list that captures all outgoing requests."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    token = "t" if enabled else None
    chat_id = "c" if enabled else None
    return TelegramNotifier(bot_token=token, chat_id=chat_id, client=client), requests


# -----------------------------------------------------------------------------
async def test_send_critical_alert_for_critical_severity():
    notifier, requests = _mock_notifier()
    finding = Finding(
        severity=Severity.CRITICAL,
        title="Remote Code Execution",
        source_tool="nuclei",
        cve="CVE-2021-44228",
        description="Log4j vulnerability",
        evidence={"template_id": "cve-2021-44228", "matched_at": "https://example.com/api"},
    )
    result = await notifier.send_critical_alert(finding)
    assert result is True
    assert len(requests) == 1
    await notifier.aclose()


async def test_send_critical_alert_for_high_severity():
    notifier, requests = _mock_notifier()
    finding = Finding(
        severity=Severity.HIGH,
        title="SQL Injection",
        source_tool="nuclei",
    )
    result = await notifier.send_critical_alert(finding)
    assert result is True
    assert len(requests) == 1
    await notifier.aclose()


async def test_send_critical_alert_skips_low():
    notifier, requests = _mock_notifier()
    finding = Finding(
        severity=Severity.LOW,
        title="Version Disclosure",
        source_tool="whatweb",
    )
    result = await notifier.send_critical_alert(finding)
    assert result is False
    assert len(requests) == 0
    await notifier.aclose()


async def test_send_critical_alert_skips_info():
    notifier, requests = _mock_notifier()
    finding = Finding(
        severity=Severity.INFO,
        title="HTTP Header Found",
        source_tool="nuclei",
    )
    result = await notifier.send_critical_alert(finding)
    assert result is False
    assert len(requests) == 0
    await notifier.aclose()


async def test_disabled_notifier_noop():
    notifier, requests = _mock_notifier(enabled=False)
    finding = Finding(
        severity=Severity.CRITICAL,
        title="Critical RCE",
        source_tool="nuclei",
    )
    result = await notifier.send_critical_alert(finding)
    assert result is False
    assert len(requests) == 0
    await notifier.aclose()
