"""Async WhatWeb wrapper (HTTP technology fingerprinting).

WhatWeb's ``--log-json=/dev/stdout`` flag writes a JSON array to stdout::

    [
      {
        "target": "http://example.com",
        "http_status": 200,
        "plugins": {
          "nginx":  [{"version": ["1.18.0"]}],
          "HTML5":  [{}],
          "Cookies": [{"string": ["session"]}]
        }
      }
    ]

We turn each detected plugin into a :class:`AssetType.TECHNOLOGY` record
(plus a single :class:`AssetType.HOST` carrying the HTTP status). Since
WhatWeb resolves and connects to the target, the wrapper still does a
scope check first — defense in depth.
"""

from __future__ import annotations

import json
from typing import Any

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool


class WhatWebWrapper(BaseTool):
    """Run WhatWeb and emit TECHNOLOGY assets per detected plugin."""

    name = "whatweb"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 300.0,
        aggression: int = 1,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)
        # Aggression 1 = passive (banner only); 3+ = active probing.
        # We default to passive to stay polite on continuous monitoring.
        if aggression not in (1, 3, 4):
            raise ValueError("whatweb aggression must be 1, 3 or 4")
        self._aggression = aggression

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        url = target if "://" in target else f"http://{target}"
        return (
            "whatweb",
            "--log-json=/dev/stdout",
            "--color=never",
            "--quiet",
            f"--aggression={self._aggression}",
            url,
        )

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        text = result.stdout.strip()
        if not text:
            return _empty_result(self.name, target, result)

        records = _load_records(text)
        assets: list[Asset] = []

        for record in records:
            target_url = str(record.get("target") or target)
            http_status = record.get("http_status")
            if http_status is not None:
                assets.append(
                    Asset(
                        asset_type=AssetType.HOST,
                        value=target_url,
                        source_tool=self.name,
                        extra={"http_status": http_status},
                    )
                )

            plugins = record.get("plugins") or {}
            if not isinstance(plugins, dict):
                continue
            for plugin_name, entries in plugins.items():
                version = _first_version(entries)
                value = f"{plugin_name} {version}".strip() if version else plugin_name
                assets.append(
                    Asset(
                        asset_type=AssetType.TECHNOLOGY,
                        value=value,
                        source_tool=self.name,
                        extra={
                            "plugin": plugin_name,
                            "version": version,
                            "url": target_url,
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


# -----------------------------------------------------------------------------
def _empty_result(tool: str, target: str, result: CommandResult) -> ToolRunResult:
    return ToolRunResult(
        tool=tool,
        target=target,
        started_at=result.started_at,
        completed_at=result.completed_at,
        return_code=result.return_code,
        assets=[],
        raw_excerpt=result.stdout[:2048],
    )


def _load_records(text: str) -> list[dict[str, Any]]:
    """Parse WhatWeb output into a list of dict records.

    WhatWeb usually emits a JSON array, but with multiple targets it can
    emit one JSON object per line. Both shapes are handled.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
        return records

    if isinstance(parsed, list):
        return [r for r in parsed if isinstance(r, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _first_version(entries: Any) -> str | None:
    """Pull the first ``version`` string out of a WhatWeb plugin entry list."""
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        versions = entry.get("version")
        if isinstance(versions, list) and versions:
            v = versions[0]
            if isinstance(v, str) and v.strip():
                return v.strip()
        elif isinstance(versions, str) and versions.strip():
            return versions.strip()
    return None
