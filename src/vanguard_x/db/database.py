"""Async SQLAlchemy engine + repository for VANGUARD-X.

Two responsibilities, intentionally separated:

- :class:`Database` owns the async engine and session factory. Created once
  per process. Call :meth:`Database.create_all` at startup.
- :class:`ScanRepository` is the *only* public surface for agents that need
  to read / write scan state. It hides SQLAlchemy from the agent code.
"""

from __future__ import annotations

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

from vanguard_x.db.schema import AssetRow, Base, FindingRow, ScanRow
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import (
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
