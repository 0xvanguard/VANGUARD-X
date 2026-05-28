"""Async Gobuster wrapper (directory/file brute-forcing).

Gobuster dir mode in quiet mode emits one discovered path per line::

    /admin (Status: 200) [Size: 1234]
    /login (Status: 302) [Size: 0]

The wrapper parses each line with a regex and emits URL assets.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool

_LINE_PATTERN = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")


class GobusterResult(BaseModel):
    """Intermediate parse model for a single gobuster result line."""

    model_config = ConfigDict(extra="forbid")

    path: str
    status_code: int
    size: int | None = None


class GobusterWrapper(BaseTool):
    """Run Gobuster and emit URL assets for discovered paths."""

    name = "gobuster"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 600.0,
        wordlist_path: str = "/wordlists/common.txt",
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)
        self._wordlist_path = wordlist_path

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        return (
            "gobuster",
            "dir",
            "-u",
            f"http://{target}",
            "-w",
            self._wordlist_path,
            "-q",
            "-n",
            "--no-error",
            "-t",
            "50",
        )

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        assets: list[Asset] = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE_PATTERN.match(line)
            if not m:
                continue

            gr = GobusterResult(
                path=m.group(1),
                status_code=int(m.group(2)),
                size=int(m.group(3)) if m.group(3) else None,
            )

            full_url = f"http://{target}{gr.path}"
            extra: dict[str, int] = {"status_code": gr.status_code}
            if gr.size is not None:
                extra["size"] = gr.size

            assets.append(
                Asset(
                    asset_type=AssetType.URL,
                    value=full_url,
                    source_tool=self.name,
                    extra=extra,
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
