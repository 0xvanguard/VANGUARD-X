"""Cross-scan change detection.

Continuous monitoring is only useful if it tells the operator *what changed*
between runs — a fresh subdomain that wasn't there yesterday is much more
interesting than the 200th time we re-confirm the same nginx banner.

:class:`ChangeDetector` compares the current scan against the most recent
**previously completed** scan of the same target and emits a
:class:`~vanguard_x.models.ScanDiff`. The first scan of a target is treated
as the *baseline*: every asset is "new" but ``is_baseline`` lets notifiers
suppress the pager.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from vanguard_x.logging_setup import get_logger
from vanguard_x.models import AssetIdentity, AssetType, ScanDiff

if TYPE_CHECKING:
    from vanguard_x.db.database import ScanRepository
    from vanguard_x.db.schema import AssetRow

_log = get_logger(__name__)


class ChangeDetector:
    """Compare a scan against the previous completed scan of the same target."""

    def __init__(self, repository: ScanRepository) -> None:
        self._repo = repository

    async def detect(self, scan_id: int) -> ScanDiff:
        """Compute the asset diff for ``scan_id`` against history."""
        scan = await self._repo.get_scan(scan_id)
        if scan is None:
            raise LookupError(f"scan {scan_id} not found")

        current_rows = await self._repo.list_assets(scan_id)
        current_index = _index(current_rows)

        previous = await self._repo.previous_completed_scan(
            target=scan.target, before_scan_id=scan_id
        )
        if previous is None:
            diff = ScanDiff(
                scan_id=scan_id,
                target=scan.target,
                previous_scan_id=None,
                new=list(current_index.values()),
                removed=[],
            )
            _log.info(
                "changes.baseline",
                scan_id=scan_id,
                target=scan.target,
                assets=len(diff.new),
            )
            return diff

        previous_rows = await self._repo.list_assets(previous.id)
        previous_index = _index(previous_rows)

        new_keys = current_index.keys() - previous_index.keys()
        removed_keys = previous_index.keys() - current_index.keys()

        diff = ScanDiff(
            scan_id=scan_id,
            target=scan.target,
            previous_scan_id=previous.id,
            new=[current_index[k] for k in sorted(new_keys)],
            removed=[previous_index[k] for k in sorted(removed_keys)],
        )
        _log.info(
            "changes.detected",
            scan_id=scan_id,
            previous_scan_id=previous.id,
            target=scan.target,
            new=len(diff.new),
            removed=len(diff.removed),
        )
        return diff


def _index(rows: list[AssetRow]) -> dict[tuple[str, str], AssetIdentity]:
    """Index assets by ``(asset_type, lower(value))`` for set arithmetic."""
    out: dict[tuple[str, str], AssetIdentity] = {}
    for row in rows:
        try:
            atype = AssetType(row.asset_type)
        except ValueError:
            # Forward-compatible: unknown asset types from a future schema
            # are silently bucketed as HOST so we don't lose them in alerts.
            atype = AssetType.HOST
        identity = AssetIdentity(
            asset_type=atype,
            value=row.value,
            source_tool=row.source_tool,
            extra=dict(row.extra or {}),
        )
        out.setdefault(identity.key(), identity)
    return out
