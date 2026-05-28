"""ATTACK agent -- Phase 2 Month 3.

Pipeline:
    scope check -> [Nuclei | Gobuster] per target (concurrent)
    -> persist findings + assets -> critical alerts -> summarise

Failure semantics identical to ReconAgent:
- ScopeViolation propagates and cancels.
- Other tool exceptions downgraded to partial results.
"""

from __future__ import annotations

import asyncio

from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.db.database import ScanRepository
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import Asset, Finding, ScanSummary, Severity
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools import BaseTool
from vanguard_x.tools.gobuster import GobusterWrapper
from vanguard_x.tools.nuclei import NucleiWrapper

_log = get_logger(__name__)


class AttackAgent:
    """Runs vulnerability scanning tools in parallel against multiple targets."""

    AGENT_NAME = "attack"

    def __init__(
        self,
        *,
        nuclei: NucleiWrapper,
        gobuster: GobusterWrapper,
        scope: ScopeEnforcer,
        repository: ScanRepository,
        notifier: TelegramNotifier,
    ) -> None:
        self._tools: tuple[BaseTool, ...] = (nuclei, gobuster)
        self._scope = scope
        self._repository = repository
        self._notifier = notifier

    # ------------------------------------------------------------------
    async def run(self, targets: list[str], *, scope_label: str = "external") -> ScanSummary:
        """Execute the full ATTACK pipeline and return a :class:`ScanSummary`."""
        _log.info("attack.start", targets=targets, scope=scope_label)

        # Pre-flight: scope check ALL targets before any work.
        for t in targets:
            self._scope.assert_authorized(t)

        primary_target = targets[0] if targets else "unknown"
        scan_id = await self._repository.create_scan(
            target=primary_target, scope_label=scope_label, agent=self.AGENT_NAME
        )
        await self._repository.mark_running(scan_id)

        try:
            # Run all tools against all targets in parallel.
            tasks = [
                self._run_tool(tool, target, scan_id) for target in targets for tool in self._tools
            ]
            results = await asyncio.gather(*tasks)

            all_findings: list[Finding] = []
            all_assets: list[Asset] = []
            for r in results:
                if r is not None:
                    all_assets.extend(r[0])
                    all_findings.extend(r[1])

            # Persist.
            await self._repository.save_attack_result(scan_id, all_findings, all_assets)

            # Finalise.
            await self._repository.mark_done(scan_id)
            summary = await self._repository.scan_summary(scan_id)

            # Send critical alerts for high/critical findings.
            for finding in all_findings:
                if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                    await self._notifier.send_critical_alert(finding)

            await self._notifier.send_summary(summary)
            return summary

        except ScopeViolation as exc:
            await self._repository.mark_scope_violation(scan_id, error=str(exc))
            raise
        except Exception as exc:
            await self._repository.mark_failed(scan_id, error=str(exc))
            raise

    # ------------------------------------------------------------------
    async def _run_tool(
        self, tool: BaseTool, target: str, scan_id: int
    ) -> tuple[list[Asset], list[Finding]] | None:
        """Run a single tool, downgrading non-scope errors to partial results."""
        try:
            result = await tool.run(target)
        except ScopeViolation:
            raise
        except Exception as exc:
            _log.error("attack.tool_failed", scan_id=scan_id, tool=tool.name, error=str(exc))
            return None
        return (list(result.assets), list(result.findings))
