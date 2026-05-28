"""Telegram bot notifier.

Two-mode design:

- **Disabled**: when token or chat_id are missing the notifier becomes a
  no-op that only logs at DEBUG level. CI / local dev runs without secrets
  produce zero side-effects.
- **Enabled**: posts to ``https://api.telegram.org/bot<token>/...`` with
  HTML formatting and a configurable :mod:`httpx` client for testability.

The notifier never raises on transport errors; failures are logged and
swallowed so that scan pipelines are not aborted by a flaky chat platform.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

import httpx

from vanguard_x.config import Settings
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import AssetIdentity, ScanDiff, ScanStatus, ScanSummary, Severity

_log = get_logger(__name__)

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO: "*",
    Severity.LOW: "~",
    Severity.MEDIUM: "!",
    Severity.HIGH: "!!",
    Severity.CRITICAL: "!!!",
}

_LEVEL_TAG: dict[str, str] = {
    "DEBUG": "[DEBUG]",
    "INFO": "[INFO]",
    "WARNING": "[WARN]",
    "ERROR": "[ERROR]",
    "CRITICAL": "[CRITICAL]",
}


class TelegramNotifier:
    """Async Telegram client. Construct via :meth:`from_settings`."""

    BASE_URL = "https://api.telegram.org/bot{token}"

    def __init__(
        self,
        bot_token: str | None,
        chat_id: str | None,
        *,
        client: httpx.AsyncClient | None = None,
        request_timeout: float = 15.0,
    ) -> None:
        self._token = bot_token
        self._chat_id = chat_id
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=request_timeout)

    # ------------------------------------------------------------------
    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> TelegramNotifier:
        return cls(
            bot_token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            client=client,
        )

    @property
    def enabled(self) -> bool:
        return bool(self._token and self._chat_id)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> TelegramNotifier:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        await self.aclose()

    # ------------------------------------------------------------------
    async def send_alert(self, text: str, *, level: str = "INFO") -> bool:
        """Send a free-form alert. Returns ``True`` on successful POST."""
        tag = _LEVEL_TAG.get(level.upper(), "[INFO]")
        body = f"<b>{html.escape(tag)}</b>\n{html.escape(text)}"
        return await self._post_message(body)

    async def send_summary(self, summary: ScanSummary) -> bool:
        """Send a structured scan summary."""
        return await self._post_message(self._render_summary(summary))

    async def send_change_alert(self, diff: ScanDiff) -> bool:
        """Send a structured cross-scan change alert.

        No-op (returns ``False``) when the diff is the baseline scan or has
        no changes — :class:`ContinuousMonitor` should rely on this so the
        first scan of a new target does not page the operator.
        """
        if diff.is_baseline or not diff.has_changes:
            _log.debug(
                "telegram.change_alert_skipped",
                scan_id=diff.scan_id,
                is_baseline=diff.is_baseline,
                has_changes=diff.has_changes,
            )
            return False
        return await self._post_message(self._render_change_alert(diff))

    async def send_report_file(self, path: Path, *, caption: str = "") -> bool:
        """Upload a report artefact (PDF / HTML) as a Telegram document."""
        if not self.enabled:
            _log.debug("telegram.disabled", action="send_report_file", path=str(path))
            return False
        if not path.exists() or not path.is_file():
            _log.warning("telegram.report_missing", path=str(path))
            return False

        url = self.BASE_URL.format(token=self._token) + "/sendDocument"
        try:
            with path.open("rb") as fh:
                files = {"document": (path.name, fh, "application/octet-stream")}
                data = {"chat_id": self._chat_id, "caption": caption[:1024]}
                resp = await self._client.post(url, data=data, files=files)
            return self._check_response(resp, action="sendDocument")
        except httpx.HTTPError as exc:
            _log.error("telegram.send_report_failed", error=str(exc), path=str(path))
            return False

    # ------------------------------------------------------------------
    async def _post_message(self, html_text: str) -> bool:
        if not self.enabled:
            _log.debug("telegram.disabled", preview=html_text[:80])
            return False

        url = self.BASE_URL.format(token=self._token) + "/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": html_text[:4096],  # Telegram message-length cap
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            resp = await self._client.post(url, json=payload)
            return self._check_response(resp, action="sendMessage")
        except httpx.HTTPError as exc:
            _log.error("telegram.send_failed", error=str(exc))
            return False

    @staticmethod
    def _check_response(resp: httpx.Response, *, action: str) -> bool:
        if resp.status_code >= 400:
            _log.error(
                "telegram.api_error",
                action=action,
                status=resp.status_code,
                body=resp.text[:300],
            )
            return False
        return True

    # ------------------------------------------------------------------
    @staticmethod
    def _render_summary(s: ScanSummary) -> str:
        status_tag = "OK" if s.status is ScanStatus.DONE else s.status.value.upper()
        lines: list[str] = [
            f"<b>VANGUARD-X RECON [{html.escape(status_tag)}]</b>",
            f"Target: <code>{html.escape(s.target)}</code>",
            f"Scope: <code>{html.escape(s.scope_label)}</code>",
            f"Scan ID: <code>{s.scan_id}</code>",
        ]
        if s.duration_seconds is not None:
            lines.append(f"Duration: {s.duration_seconds:.1f}s")
        lines.append(f"Assets discovered: <b>{s.asset_count}</b>")
        lines.append(f"Findings: <b>{s.finding_count}</b>")

        if s.findings_by_severity:
            sev_lines = []
            for sev in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ):
                count = s.findings_by_severity.get(sev, 0)
                if count:
                    sev_lines.append(f"  {_SEVERITY_EMOJI[sev]} {sev.value}: {count}")
            if sev_lines:
                lines.append("Severity breakdown:")
                lines.extend(sev_lines)

        if s.error:
            lines.append(f"Error: <code>{html.escape(s.error[:300])}</code>")

        lines.append(f"Started: {_fmt_dt(s.started_at)}")
        if s.completed_at:
            lines.append(f"Completed: {_fmt_dt(s.completed_at)}")

        return "\n".join(lines)

    @staticmethod
    def _render_change_alert(diff: ScanDiff) -> str:
        """Render a :class:`ScanDiff` for Telegram (HTML mode)."""
        lines: list[str] = [
            "<b>VANGUARD-X CHANGE DETECTED</b>",
            f"Target: <code>{html.escape(diff.target)}</code>",
            f"Scan: <code>{diff.scan_id}</code> (vs <code>{diff.previous_scan_id}</code>)",
            f"New assets: <b>{len(diff.new)}</b>  Removed assets: <b>{len(diff.removed)}</b>",
        ]
        if diff.new:
            lines.append("")
            lines.append("<b>+ New:</b>")
            lines.extend(_render_asset_lines(diff.new, prefix="+ "))
        if diff.removed:
            lines.append("")
            lines.append("<b>- Removed:</b>")
            lines.extend(_render_asset_lines(diff.removed, prefix="- "))
        return "\n".join(lines)


def _render_asset_lines(
    assets: list[AssetIdentity],
    *,
    prefix: str,
    cap: int = 25,
) -> list[str]:
    """Format a sorted asset list with a per-message cap to stay under 4 KiB."""
    grouped: dict[str, list[AssetIdentity]] = {}
    for a in assets:
        grouped.setdefault(a.asset_type.value, []).append(a)

    out: list[str] = []
    rendered = 0
    for asset_type in sorted(grouped):
        items = grouped[asset_type]
        out.append(f"  <i>{html.escape(asset_type)}</i> ({len(items)})")
        for a in items:
            if rendered >= cap:
                remaining = sum(len(v) for v in grouped.values()) - rendered
                if remaining > 0:
                    out.append(f"  ... and {remaining} more")
                return out
            out.append(f"  {prefix}<code>{html.escape(a.value)}</code>")
            rendered += 1
    return out


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
