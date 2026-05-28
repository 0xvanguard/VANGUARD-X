"""Async SQLAlchemy engine + repository for VANGUARD-X.

Two responsibilities, intentionally separated:

- :class:`Database` owns the async engine and session factory. Created once
  per process. Call :meth:`Database.create_all` at startup.
- :class:`ScanRepository` is the *only* public surface for agents that need
  to read / write scan state. It hides SQLAlchemy from the agent code.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vanguard_x.db.schema import AnalysisReportRow, AssetRow, Base, FindingRow, ScanRow
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import (
    AnalysisReport,
    Asset,
    Finding,
    ScanStatus,
    ScanSummary,
    Severity,
)

_log = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ensure_sqlite_parent_dir(url: str) -> None:
    """For ``sqlite+aiosqlite:///path/to/db`` URLs, mkdir the parent folder.

    No-op for in-memory SQLite, PostgreSQL, MySQL, ...
    """
    if not url.startswith("sqlite"):
        return
    parsed = urlparse(url)
    # SQLAlchemy SQLite URLs: sqlite+aiosqlite:///relative or ////absolute
    raw_path = parsed.path
    if not raw_path or raw_path in (":memory:", "/:memory:"):
        return
    # Drop the leading slash that comes from the URL parser.
    db_path = Path(raw_path.lstrip("/")) if not raw_path.startswith("//") else Path(raw_path)
    parent = db_path.parent
    if str(parent) and parent != Path():
        parent.mkdir(parents=True, exist_ok=True)


# =============================================================================
class Database:
    """Owns the async engine and session factory."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self._url = url
        _ensure_sqlite_parent_dir(url)
        # ``future=True`` is the default in SA 2.0; kept explicit for clarity.
        self._engine: AsyncEngine = create_async_engine(url, echo=echo, future=True)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)

    @property
    def url(self) -> str:
        return self._url

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def create_all(self) -> None:
        """Create every table declared on :class:`Base`. Idempotent."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _log.info("database.schema_ready", url=self._url)

    async def dispose(self) -> None:
        """Close the engine; safe to call multiple times."""
        await self._engine.dispose()

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session inside a transaction; rolls back on exception."""
        async with self._sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise


# =============================================================================
class ScanRepository:
    """The agent-facing API for scan persistence."""

    def __init__(self, database: Database) -> None:
        self._db = database

    # ------------------------------------------------------------------
    async def create_scan(
        self,
        *,
        target: str,
        scope_label: str = "external",
        agent: str = "recon",
    ) -> int:
        """Create a new scan in PENDING status; return its id."""
        row = ScanRow(
            target=target,
            scope_label=scope_label,
            agent=agent,
            status=ScanStatus.PENDING.value,
            started_at=_utcnow(),
        )
        async with self._db.session() as s:
            s.add(row)
            await s.flush()
            scan_id = row.id
        _log.info("scan.created", scan_id=scan_id, target=target, agent=agent)
        return scan_id

    async def mark_running(self, scan_id: int) -> None:
        await self._update_status(scan_id, ScanStatus.RUNNING)

    async def mark_done(self, scan_id: int) -> None:
        await self._finalise(scan_id, ScanStatus.DONE)

    async def mark_failed(self, scan_id: int, *, error: str) -> None:
        await self._finalise(scan_id, ScanStatus.FAILED, error=error)

    async def mark_scope_violation(self, scan_id: int, *, error: str) -> None:
        await self._finalise(scan_id, ScanStatus.SCOPE_VIOLATION, error=error)

    async def _update_status(self, scan_id: int, status: ScanStatus) -> None:
        async with self._db.session() as s:
            scan = await s.get(ScanRow, scan_id)
            if scan is None:
                raise LookupError(f"scan {scan_id} not found")
            scan.status = status.value

    async def _finalise(
        self,
        scan_id: int,
        status: ScanStatus,
        *,
        error: str | None = None,
    ) -> None:
        async with self._db.session() as s:
            scan = await s.get(ScanRow, scan_id)
            if scan is None:
                raise LookupError(f"scan {scan_id} not found")
            scan.status = status.value
            scan.completed_at = _utcnow()
            if error is not None:
                scan.error = error[:4096]  # bound the DB column to 4 KiB
        _log.info("scan.finalised", scan_id=scan_id, status=status.value)

    # ------------------------------------------------------------------
    async def persist_assets(self, scan_id: int, assets: Iterable[Asset]) -> int:
        """Insert assets for a scan, deduping on ``(asset_type, value)``.

        Returns the number of rows actually written.
        """
        seen: dict[tuple[str, str], Asset] = {}
        for a in assets:
            seen.setdefault(a.dedupe_key(), a)
        if not seen:
            return 0

        now = _utcnow()
        async with self._db.session() as s:
            for asset in seen.values():
                s.add(
                    AssetRow(
                        scan_id=scan_id,
                        asset_type=asset.asset_type.value,
                        value=asset.value,
                        source_tool=asset.source_tool,
                        extra=asset.extra,
                        first_seen=asset.discovered_at,
                        last_seen=now,
                    )
                )
        _log.info("assets.persisted", scan_id=scan_id, count=len(seen))
        return len(seen)

    async def persist_findings(self, scan_id: int, findings: Iterable[Finding]) -> int:
        """Insert findings for a scan; returns the number written."""
        rows = [
            FindingRow(
                scan_id=scan_id,
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                cve=f.cve,
                source_tool=f.source_tool,
                evidence=f.evidence,
                status=f.status.value,
                confidence=f.confidence,
                discovered_at=f.discovered_at,
            )
            for f in findings
        ]
        if not rows:
            return 0
        async with self._db.session() as s:
            s.add_all(rows)
        _log.info("findings.persisted", scan_id=scan_id, count=len(rows))
        return len(rows)

    # ------------------------------------------------------------------
    async def get_scan(self, scan_id: int) -> ScanRow | None:
        async with self._db.session() as s:
            return await s.get(ScanRow, scan_id)

    async def previous_completed_scan(
        self,
        *,
        target: str,
        before_scan_id: int,
    ) -> ScanRow | None:
        """Most recent ``DONE`` scan for ``target`` with id < ``before_scan_id``.

        Returns ``None`` if no such scan exists — the caller treats that
        as the baseline-scan case.
        """
        async with self._db.session() as s:
            stmt = (
                select(ScanRow)
                .where(ScanRow.target == target)
                .where(ScanRow.status == ScanStatus.DONE.value)
                .where(ScanRow.id < before_scan_id)
                .order_by(ScanRow.id.desc())
                .limit(1)
            )
            res = await s.execute(stmt)
            return res.scalars().first()

    async def list_assets(self, scan_id: int) -> list[AssetRow]:
        async with self._db.session() as s:
            stmt = select(AssetRow).where(AssetRow.scan_id == scan_id)
            res = await s.execute(stmt)
            return list(res.scalars().all())

    async def list_findings(self, scan_id: int) -> list[FindingRow]:
        async with self._db.session() as s:
            stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
            res = await s.execute(stmt)
            return list(res.scalars().all())

    async def save_attack_result(
        self, scan_id: int, findings: Iterable[Finding], assets: Iterable[Asset]
    ) -> tuple[int, int]:
        """Persist attack findings and assets in one call.

        Returns (findings_written, assets_written).
        """
        f_count = await self.persist_findings(scan_id, findings)
        a_count = await self.persist_assets(scan_id, assets)
        return f_count, a_count

    async def get_attack_results(self, scan_id: int) -> tuple[list[FindingRow], list[AssetRow]]:
        """Return (findings, assets) for a scan."""
        findings = await self.list_findings(scan_id)
        assets = await self.list_assets(scan_id)
        return findings, assets

    async def get_findings_by_severity(
        self, severity: Severity, *, limit: int = 100
    ) -> list[FindingRow]:
        """Query findings by severity across all scans."""
        async with self._db.session() as s:
            stmt = (
                select(FindingRow)
                .where(FindingRow.severity == severity.value)
                .order_by(FindingRow.discovered_at.desc())
                .limit(limit)
            )
            res = await s.execute(stmt)
            return list(res.scalars().all())

    async def get_pipeline_results(self, target: str) -> list[ScanSummary]:
        """Return scan summaries for a target, ordered by most recent first."""
        async with self._db.session() as s:
            stmt = (
                select(ScanRow).where(ScanRow.target == target).order_by(ScanRow.started_at.desc())
            )
            res = await s.execute(stmt)
            scans = list(res.scalars().all())

        summaries: list[ScanSummary] = []
        for scan in scans:
            summaries.append(await self.scan_summary(scan.id))
        return summaries

    async def scan_summary(self, scan_id: int) -> ScanSummary:
        """Aggregate a scan into a :class:`ScanSummary` for notifications."""
        async with self._db.session() as s:
            scan = await s.get(ScanRow, scan_id)
            if scan is None:
                raise LookupError(f"scan {scan_id} not found")

            assets = await s.execute(select(AssetRow).where(AssetRow.scan_id == scan_id))
            asset_count = len(assets.scalars().all())

            findings = await s.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))
            findings_list = list(findings.scalars().all())

            sev_counter: Counter[Severity] = Counter()
            for f in findings_list:
                try:
                    sev_counter[Severity(f.severity)] += 1
                except ValueError:
                    sev_counter[Severity.INFO] += 1

            return ScanSummary(
                scan_id=scan.id,
                target=scan.target,
                scope_label=scan.scope_label,
                status=ScanStatus(scan.status),
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                asset_count=asset_count,
                finding_count=len(findings_list),
                findings_by_severity=dict(sev_counter),
                error=scan.error,
            )

    # ------------------------------------------------------------------
    # Analysis reports (Phase 3 Month 5)
    # ------------------------------------------------------------------
    async def get_latest_completed_scan_id(self, target: str) -> int | None:
        """Return the id of the most recent DONE scan for a target, or None."""
        async with self._db.session() as s:
            stmt = (
                select(ScanRow.id)
                .where(ScanRow.target == target)
                .where(ScanRow.status == ScanStatus.DONE.value)
                .order_by(ScanRow.id.desc())
                .limit(1)
            )
            res = await s.execute(stmt)
            row = res.scalars().first()
        return row

    async def save_analysis_report(
        self, report: AnalysisReport, *, scan_id: int | None = None
    ) -> str:
        """Persist an analysis report and return its unique run_id."""
        run_id = uuid.uuid4().hex[:16]
        row = AnalysisReportRow(
            target=report.target,
            scan_id=scan_id,
            run_id=run_id,
            report_json=report.model_dump(mode="json"),
            generated_at=report.generated_at,
        )
        async with self._db.session() as s:
            s.add(row)
        _log.info("analysis_report.saved", run_id=run_id, target=report.target)
        return run_id

    async def get_analysis_report(self, target: str, run_id: str) -> AnalysisReport | None:
        """Retrieve an analysis report by target and run_id."""
        async with self._db.session() as s:
            stmt = (
                select(AnalysisReportRow)
                .where(AnalysisReportRow.target == target)
                .where(AnalysisReportRow.run_id == run_id)
            )
            res = await s.execute(stmt)
            row = res.scalars().first()
        if row is None:
            return None
        return AnalysisReport.model_validate(row.report_json)

    async def list_analysis_reports(self, target: str) -> list[tuple[str, datetime]]:
        """Return (run_id, generated_at) tuples for a target, newest first."""
        async with self._db.session() as s:
            stmt = (
                select(AnalysisReportRow.run_id, AnalysisReportRow.generated_at)
                .where(AnalysisReportRow.target == target)
                .order_by(AnalysisReportRow.generated_at.desc())
            )
            res = await s.execute(stmt)
            return [(row.run_id, row.generated_at) for row in res.all()]
