"""Async wafw00f wrapper (Web Application Firewall detection).

``wafw00f`` writes a JSON list to the path given by ``-o`` — pointing at
``/dev/stdout`` lets us collect it without a temp file::

    [
      {
        "url": "http://example.com",
        "detected": true,
        "trigger_url": "http://example.com/?random",
        "firewall": "Cloudflare",
        "manufacturer": "Cloudflare Inc."
      }
    ]

Each "detected: true" entry yields a ``TECHNOLOGY`` asset of the form
``WAF: <firewall>`` so the rest of the pipeline can correlate WAF presence
with port/service findings.
"""

from __future__ import annotations

import json
from typing import Any

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool


class WafW00fWrapper(BaseTool):
    """Run wafw00f and emit a TECHNOLOGY asset when a WAF is detected."""

    name = "wafw00f"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 300.0,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        url = target if "://" in target else f"http://{target}"
        return ("wafw00f", "-o", "/dev/stdout", "-f", "json", "-a", url)

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        text = result.stdout.strip()
        records = _load_records(text)

        assets: list[Asset] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            detected = bool(record.get("detected"))
            firewall = (record.get("firewall") or "").strip()
            manufacturer = (record.get("manufacturer") or "").strip()
            url = str(record.get("url") or target)

            if not detected or not firewall or firewall.lower() in ("none", "generic"):
                continue
            assets.append(
                Asset(
                    asset_type=AssetType.TECHNOLOGY,
                    value=f"WAF: {firewall}",
                    source_tool=self.name,
                    extra={
                        "url": url,
                        "manufacturer": manufacturer,
                        "trigger_url": record.get("trigger_url"),
                    },
                )
            )

        return ToolRunResult(
            tool=self.name,
            target=target,
            started_at=result.started_at,
            completed_at=result.completed_at,
            return_code=result.return_code,
            assets=assets,
            raw_excerpt=result.stdout[:2048],
        )


def _load_records(text: str) -> list[Any]:
    """Parse wafw00f stdout into a list, tolerating dict-or-list shapes."""
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []
