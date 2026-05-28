"""Async Subfinder wrapper (passive subdomain enumeration).

Subfinder (ProjectDiscovery) emits one JSON object per discovered
subdomain when invoked with ``-silent -all -json``::

    {"host":"api.example.com","input":"example.com","source":"crtsh"}
    {"host":"www.example.com","input":"example.com","source":"alienvault"}

The wrapper parses each line defensively (a malformed line is skipped, not
fatal) and filters to hosts under the requested target — no third-party
domains end up in the asset table even if Subfinder picks them up via
search-engine crawling.
"""

from __future__ import annotations

import json

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool


class SubfinderWrapper(BaseTool):
    """Run Subfinder and emit SUBDOMAIN assets."""

    name = "subfinder"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 600.0,
        all_sources: bool = True,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)
        self._all_sources = all_sources

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        argv: list[str] = ["subfinder", "-d", target, "-silent", "-json"]
        if self._all_sources:
            argv.append("-all")
        return tuple(argv)

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        target_lower = target.lower().lstrip(".")
        seen: set[str] = set()
        assets: list[Asset] = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Subfinder occasionally emits banner lines on stdout when
                # misconfigured; skipping is safer than aborting.
                continue
            host = (obj.get("host") or "").strip().lower()
            if not host or host in seen:
                continue
            # Stay strictly in scope: subdomain of target, never the apex
            # (which is already known) and never an unrelated host.
            if host == target_lower:
                continue
            if not host.endswith("." + target_lower):
                continue

            seen.add(host)
            source = obj.get("source") or ""
            assets.append(
                Asset(
                    asset_type=AssetType.SUBDOMAIN,
                    value=host,
                    source_tool=self.name,
                    extra={"source": source} if source else {},
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
