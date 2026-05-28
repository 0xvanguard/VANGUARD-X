"""RECON agent — Phase 1.

Pipeline (Month 2: tools run **in parallel** via :func:`asyncio.gather`):

    scope check  ->  [Nmap | theHarvester | Subfinder | WhatWeb | wafw00f]
                     ──────────── concurrent ────────────
                     -> dedupe -> persist -> diff vs history -> notify

Failure semantics:

- :class:`~vanguard_x.core.scope.ScopeViolation` from any tool propagates,
  cancels the other tasks, and marks the scan ``SCOPE_VIOLATION``.
- Any other tool exception is logged and downgraded to a partial-result;
  the scan still finalises ``DONE``.
- Unexpected errors elsewhere in the pipeline mark ``FAILED`` and re-raise.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from vanguard_x.core.changes import ChangeDetector
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.db.database import ScanRepository
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import Asset, ScanDiff, ScanSummary
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools import BaseTool
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper
from vanguard_x.tools.subfinder import SubfinderWrapper
from vanguard_x.tools.wafw00f import WafW00fWrapper
from vanguard_x.tools.whatweb import WhatWebWrapper

_log = get_logger(__name__)


class ReconAgent:
    """Discovers assets across multiple OSINT / network tools in parallel."""

    AGENT_NAME = "recon"

    def __init__(
        self,
        *,
        nmap: NmapWrapper,
        harvester: HarvesterWrapper,
        subfinder: SubfinderWrapper,
        whatweb: WhatWebWrapper,
        wafw00f: WafW00fWrapper,
        scope: ScopeEnforcer,
        repository: ScanRepository,
        notifier: TelegramNotifier,
        change_detector: ChangeDetector | None = None,
    ) -> None:
        self._tools: tuple[BaseTool, ...] = (nmap, harvester, subfinder, whatweb, wafw00f)
        self._scope = scope
        self._repository = repository
        self._notifier = notifier
        self._change_detector = change_detector or ChangeDetector(repository)

    # ------------------------------------------------------------------
    async def run(self, target: str, *, scope_label: str = "external") -> ScanSummary:
        """Execute the full RECON pipeline and return a :class:`ScanSummary`."""
        _log.info("recon.start", target=target, scope=scope_label)

        # Pre-flight scope check before any DB write.
        try:
            self._scope.assert_authorized(target)
        except ScopeViolation as exc:
            await self._notifier.send_alert(
                f"SCOPE_VIOLATION blocked: {target!r} not authorised "
                f"(allowed: {', '.join(self._scope.authorized) or '<empty>'}).",
                level="CRITICAL",
            )
            _log.error("recon.scope_violation", target=target, error=str(exc))
            raise

        scan_id = await self._repository.create_scan(
            target=target,
            scope_label=scope_label,
            agent=self.AGENT_NAME,
        )
        await self._repository.mark_running(scan_id)

        try:
            # ---- 1) Run every tool concurrently. ----------------------
            # ``asyncio.gather`` (without return_exceptions) cancels the
            # other tasks the moment one raises ScopeViolation — exactly
            # the behaviour we want for that one specific exception. All
            # other failures are absorbed by ``_run_tool`` so partial
            # results survive a flaky individual binary.
            results = await asyncio.gather(
                *(self._run_tool(tool, target, scan_id) for tool in self._tools)
            )

            collected: list[Asset] = []
            for r in results:
                if r is not None:
                    collected.extend(r)

            # ---- 2) Persist (repository handles dedup at write time) --
            written = await self._repository.persist_assets(scan_id, _dedupe(collected))

            # ---- 3) Finalise + summary --------------------------------
            await self._repository.mark_done(scan_id)
            summary = await self._repository.scan_summary(scan_id)

            # ---- 4) Change detection ---------------------------------
            diff: ScanDiff | None = None
            try:
                diff = await self._change_detector.detect(scan_id)
            except Exception as exc:
                _log.error("recon.diff_failed", scan_id=scan_id, error=str(exc))

            # ---- 5) Notify ------------------------------------------
            await self._notifier.send_summary(summary)
            if diff is not None and diff.has_changes and not diff.is_baseline:
                await self._notifier.send_change_alert(diff)

            _log.info(
                "recon.complete",
                scan_id=scan_id,
                assets_persisted=written,
                duration=summary.duration_seconds,
                new=len(diff.new) if diff else 0,
                removed=len(diff.removed) if diff else 0,
            )
            return summary

        except ScopeViolation as exc:
            await self._repository.mark_scope_violation(scan_id, error=str(exc))
            raise
        except Exception as exc:
            await self._repository.mark_failed(scan_id, error=str(exc))
            await self._notifier.send_alert(
                f"RECON failed for target={target}: {exc}",
                level="ERROR",
            )
            _log.exception("recon.failed", scan_id=scan_id)
            raise

    # ------------------------------------------------------------------
    async def _run_tool(
        self,
        tool: BaseTool,
        target: str,
        scan_id: int,
    ) -> list[Asset] | None:
        """Run a single tool, downgrading non-scope errors to partial results."""
        try:
            result = await tool.run(target)
        except ScopeViolation:
            # Re-raise so ``asyncio.gather`` cancels the sibling tool
            # tasks and the agent records SCOPE_VIOLATION in the DB.
            raise
        except Exception as exc:
            _log.error(
                "recon.tool_failed",
                scan_id=scan_id,
                tool=tool.name,
                error=str(exc),
            )
            return None
        _log.info(
            "recon.tool_done",
            scan_id=scan_id,
            tool=tool.name,
            assets=len(result.assets),
            rc=result.return_code,
        )
        return list(result.assets)


def _dedupe(assets: Iterable[Asset]) -> list[Asset]:
    """Return assets keyed by ``(asset_type, value.lower())`` — first wins."""
    seen: dict[tuple[str, str], Asset] = {}
    for a in assets:
        seen.setdefault(a.dedupe_key(), a)
    return list(seen.values())
