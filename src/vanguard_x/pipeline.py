"""Pipeline orchestrator -- Recon -> Attack.

Thin coordinator: runs recon to discover targets, extracts subdomains
and URLs from recon assets, then passes them to the attack agent.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vanguard_x.agents.attack import AttackAgent
from vanguard_x.agents.recon import ReconAgent
from vanguard_x.db.database import ScanRepository
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import AssetType, ScanSummary, Severity
from vanguard_x.notifications.telegram import TelegramNotifier

_log = get_logger(__name__)


class PipelineResult(BaseModel):
    """Result of a full Recon -> Attack pipeline run."""

    model_config = ConfigDict(extra="forbid")

    recon_summary: ScanSummary
    attack_summary: ScanSummary | None = None
    total_findings: int = 0
    critical_count: int = Field(default=0)


class PipelineOrchestrator:
    """Chains Recon and Attack agents into a single pipeline."""

    def __init__(
        self,
        *,
        recon_agent: ReconAgent,
        attack_agent: AttackAgent,
        repository: ScanRepository,
        notifier: TelegramNotifier,
    ) -> None:
        self._recon = recon_agent
        self._attack = attack_agent
        self._repository = repository
        self._notifier = notifier

    async def run(self, target: str, *, scope_label: str = "external") -> PipelineResult:
        """Execute the full Recon -> Attack pipeline."""
        _log.info("pipeline.start", target=target, scope=scope_label)

        # Phase 1: Recon.
        recon_summary = await self._recon.run(target, scope_label=scope_label)

        # Extract targets from recon assets.
        attack_targets = await self._extract_targets(recon_summary.scan_id, target)

        if not attack_targets:
            _log.info("pipeline.no_targets", target=target)
            return PipelineResult(recon_summary=recon_summary)

        # Phase 2: Attack.
        attack_summary = await self._attack.run(attack_targets, scope_label=scope_label)

        critical_count = attack_summary.findings_by_severity.get(Severity.CRITICAL, 0)

        return PipelineResult(
            recon_summary=recon_summary,
            attack_summary=attack_summary,
            total_findings=attack_summary.finding_count,
            critical_count=critical_count,
        )

    async def _extract_targets(self, scan_id: int, original_target: str) -> list[str]:
        """Extract attack targets from recon assets (subdomains + original).

        Only subdomains are extracted (not raw IPs) since those are the
        relevant attack surface for tools like Nuclei and Gobuster.
        """
        assets = await self._repository.list_assets(scan_id)
        targets: set[str] = {original_target}
        for asset in assets:
            if asset.asset_type == AssetType.SUBDOMAIN.value:
                targets.add(asset.value)
        return sorted(targets)
