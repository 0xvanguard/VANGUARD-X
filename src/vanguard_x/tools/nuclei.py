"""Async Nuclei wrapper (vulnerability scanning).

Nuclei (ProjectDiscovery) emits one JSON object per finding when invoked
with ``-jsonl -silent``::

    {"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical",...},"matched-at":"https://example.com/api",...}

The wrapper parses each line defensively and maps to Finding + Asset objects.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import (
    Asset,
    AssetType,
    Finding,
    FindingStatus,
    Severity,
    ToolRunResult,
)
from vanguard_x.tools import BaseTool

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiFinding(BaseModel):
    """Intermediate parse model for a single nuclei JSONL line."""

    model_config = ConfigDict(extra="forbid")

    template_id: str
    name: str
    severity: Severity
    matched_at: str
    matcher_name: str = ""
    description: str = ""
    cve: str | None = None


class NucleiWrapper(BaseTool):
    """Run Nuclei and emit Finding + Asset objects."""

    name = "nuclei"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 600.0,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        return ("nuclei", "-u", target, "-jsonl", "-silent", "-nc")

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        assets: list[Asset] = []
        findings: list[Finding] = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = obj.get("info") or {}
            template_id = obj.get("template-id", "")
            name = info.get("name", "")
            severity_raw = (info.get("severity") or "").lower()
            matched_at = obj.get("matched-at", "")
            matcher_name = obj.get("matcher-name", "")
            description = info.get("description", "")

            if not template_id or not matched_at:
                continue

            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)

            # Extract CVE from reference list
            cve: str | None = None
            references = info.get("reference") or []
            for ref in references:
                if _CVE_RE.match(ref):
                    cve = ref.upper()
                    break

            nf = NucleiFinding(
                template_id=template_id,
                name=name,
                severity=severity,
                matched_at=matched_at,
                matcher_name=matcher_name,
                description=description,
                cve=cve,
            )

            findings.append(
                Finding(
                    severity=nf.severity,
                    title=nf.name,
                    description=nf.description,
                    cve=nf.cve,
                    source_tool=self.name,
                    evidence={
                        "template_id": nf.template_id,
                        "matcher_name": nf.matcher_name,
                        "matched_at": nf.matched_at,
                    },
                    confidence=100,
                    status=FindingStatus.OPEN,
                    asset_value=nf.matched_at,
                )
            )

            assets.append(
                Asset(
                    asset_type=AssetType.URL,
                    value=nf.matched_at,
                    source_tool=self.name,
                )
            )

        return ToolRunResult(
            tool=self.name,
            target=target,
            started_at=result.started_at,
            completed_at=result.completed_at,
            return_code=result.return_code,
            assets=assets,
            findings=findings,
            raw_excerpt=result.stdout[:2048],
        )
