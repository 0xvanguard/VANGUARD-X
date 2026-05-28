"""RECON agent — Phase 1 / Month 1.

Pipeline (sequential for now; Phase 2 will parallelise):

    scope check  →  Nmap  →  theHarvester  →  dedupe  →  persist  →  notify

Failure semantics:

- :class:`~vanguard_x.core.scope.ScopeViolation` → scan marked
  ``SCOPE_VIOLATION``, Telegram alert, exception re-raised.
- A tool returning non-zero or producing zero assets does **not** abort
  the run; partial results are still persisted.
- Any other unexpected exception → scan marked ``FAILED``, alert sent,
  exception re-raised so the caller sees a real traceback.
"""

from __future__ import annotations

from collections.abc import Iterable

from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.db.database import ScanRepository
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import Asset, ScanSummary
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper

_log = get_logger(__name__)


class ReconAgent:
    """Discovers assets across multiple OSINT / network tools."""

    AGENT_NAME = "recon"

    def __init__(
        self,
        *,
        nmap: NmapWrapper,
        harvester: HarvesterWrapper,
        scope: ScopeEnforcer,
        repository: ScanRepository,
        notifier: TelegramNotifier,
    ) -> None:
        self._nmap = nmap
        self._harvester = harvester
        self._scope = scope
        self._repository = repository
        self._notifier = notifier

    # ------------------------------------------------------------------
    async def run(self, target: str, *, scope_label: str = "external") -> ScanSummary:
        """Execute the full RECON pipeline and return a :class:`ScanSummary`.

        Always returns a summary (or raises). Callers can inspect ``status``
        to distinguish a clean run from a partial / scope-violated one.
        """
        _log.info("recon.start", target=target, scope=scope_label)

        # Pre-flight scope check before *any* DB write — keeps the audit log
        # honest about what was requested vs. what actually ran.
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
            collected: list[Asset] = []

            # 1) Nmap — port / service discovery -----------------------------
            try:
                nmap_result = await self._nmap.run(target)
                collected.extend(nmap_result.assets)
                _log.info(
                    "recon.nmap_done",
                    scan_id=scan_id,
                    assets=len(nmap_result.assets),
                    rc=nmap_result.return_code,
                )
            except ScopeViolation:
                raise
            except Exception as exc:
                _log.error("recon.nmap_failed", scan_id=scan_id, error=str(exc))

            # 2) theHarvester — passive OSINT ------------------------------
            try:
                harvester_result = await self._harvester.run(target)
                collected.extend(harvester_result.assets)
                _log.info(
                    "recon.harvester_done",
                    scan_id=scan_id,
                    assets=len(harvester_result.assets),
                    rc=harvester_result.return_code,
                )
            except ScopeViolation:
                raise
            except Exception as exc:
                _log.error("recon.harvester_failed", scan_id=scan_id, error=str(exc))

            # 3) Persist (repository handles dedup) ------------------------
            written = await self._repository.persist_assets(scan_id, _dedupe(collected))

            # 4) Finalise + summary ----------------------------------------
            await self._repository.mark_done(scan_id)
            summary = await self._repository.scan_summary(scan_id)
            await self._notifier.send_summary(summary)

            _log.info(
                "recon.complete",
                scan_id=scan_id,
                assets_persisted=written,
                duration=summary.duration_seconds,
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


def _dedupe(assets: Iterable[Asset]) -> list[Asset]:
    """Return a list of assets keyed by ``(asset_type, value.lower())``.

    The first occurrence wins so the original ``source_tool`` is preserved.
    """
    seen: dict[tuple[str, str], Asset] = {}
    for a in assets:
        seen.setdefault(a.dedupe_key(), a)
    return list(seen.values())
