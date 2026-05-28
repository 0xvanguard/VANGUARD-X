"""Tests for the Telegram notifier."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx

from vanguard_x.config import Settings
from vanguard_x.models import ScanStatus, ScanSummary, Severity
from vanguard_x.notifications.telegram import TelegramNotifier


def _summary() -> ScanSummary:
    started = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    completed = datetime(2024, 1, 1, 0, 0, 30, tzinfo=UTC)
    return ScanSummary(
        scan_id=42,
        target="example.com",
        scope_label="external",
        status=ScanStatus.DONE,
        started_at=started,
        completed_at=completed,
        asset_count=5,
        finding_count=2,
        findings_by_severity={Severity.CRITICAL: 1, Severity.MEDIUM: 1},
    )


def _client_returning(response: httpx.Response) -> httpx.AsyncClient:
    """Build an httpx AsyncClient whose transport always yields ``response``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return response

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# -----------------------------------------------------------------------------
async def test_disabled_when_credentials_missing():
    notifier = TelegramNotifier(bot_token=None, chat_id=None)
    assert not notifier.enabled

    # All methods are no-ops that return False but never raise.
    assert await notifier.send_alert("hello") is False
    assert await notifier.send_summary(_summary()) is False
    await notifier.aclose()


async def test_send_alert_posts_to_send_message():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["json"] = request.read().decode()
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)
    ok = await notifier.send_alert("hello world", level="ERROR")
    assert ok is True
    assert "/sendMessage" in captured["url"]  # type: ignore[operator]
    assert "hello world" in captured["json"]  # type: ignore[operator]
    await notifier.aclose()


async def test_send_alert_returns_false_on_4xx():
    notifier = TelegramNotifier(
        bot_token="t",
        chat_id="c",
        client=_client_returning(httpx.Response(403, text="forbidden")),
    )
    assert await notifier.send_alert("x") is False
    await notifier.aclose()


async def test_send_alert_returns_false_on_transport_error():
    def handler(_request):  # type: ignore[no-untyped-def]
        raise httpx.ConnectError("boom")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)
    assert await notifier.send_alert("x") is False
    await notifier.aclose()


async def test_send_summary_renders_severity_breakdown():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)
    await notifier.send_summary(_summary())

    body = captured["body"]
    assert "VANGUARD-X RECON" in body
    assert "example.com" in body
    assert "critical" in body
    assert "Assets discovered" in body
    await notifier.aclose()


async def test_send_report_file_uploads(tmp_path: Path):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.read().decode(errors="replace")
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    notifier = TelegramNotifier(bot_token="t", chat_id="c", client=client)

    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF-fake")

    ok = await notifier.send_report_file(report, caption="weekly summary")
    assert ok is True
    assert "/sendDocument" in captured["url"]
    assert "weekly summary" in captured["body"]
    await notifier.aclose()


async def test_send_report_file_missing_returns_false(tmp_path: Path):
    notifier = TelegramNotifier(bot_token="t", chat_id="c")
    assert await notifier.send_report_file(tmp_path / "nope.pdf") is False
    await notifier.aclose()


# -----------------------------------------------------------------------------
def test_from_settings_factory():
    settings = Settings(
        authorized_targets="example.com",
        telegram_bot_token="t",
        telegram_chat_id="c",
    )
    notifier = TelegramNotifier.from_settings(settings)
    assert notifier.enabled
