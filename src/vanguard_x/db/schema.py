"""SQLAlchemy 2.0 declarative schema.

Tables (designed for the full Phase 1-6 lifecycle, but only ``scans``,
``assets``, ``findings`` and ``reports`` are populated in Month 1):

- ``scans``     : one row per agent run (RECON, ATTACK, ...).
- ``assets``    : everything RECON discovers (hosts, ports, subdomains, ...).
- ``findings``  : potential vulnerabilities (populated from Phase 2).
- ``reports``   : generated PDF / HTML artefacts (Phase 4).

Identity strategy: surrogate integer primary keys plus a natural-key
constraint on ``(scan_id, asset_type, value)`` so the same asset is never
duplicated within a single scan.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from vanguard_x.models import (
    AssetType,
    FindingStatus,
    ScanStatus,
    Severity,
)


class UTCDateTime(TypeDecorator[datetime]):
    """``DateTime(timezone=True)`` that round-trips correctly on SQLite.

    SQLite has no native timezone-aware datetime, so SQLAlchemy stores
    naïve UTC strings and returns them naïve. We coerce them back to UTC
    on the way out so application code can safely rely on ``tzinfo``.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base for all VANGUARD-X tables."""

    type_annotation_map = {
        dict[str, Any]: JSON,
        datetime: UTCDateTime,
    }


# -----------------------------------------------------------------------------
class ScanRow(Base):
    """A single agent run."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    scope_label: Mapped[str] = mapped_column(String(64), default="external")
    agent: Mapped[str] = mapped_column(String(32), default="recon")
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    assets: Mapped[list[AssetRow]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    reports: Mapped[list[ReportRow]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (Index("ix_scans_status_started_at", "status", "started_at"),)


# -----------------------------------------------------------------------------
class AssetRow(Base):
    """A discovered asset (host, port, subdomain, technology, ...)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_type: Mapped[str] = mapped_column(String(32), default=AssetType.HOST.value)
    value: Mapped[str] = mapped_column(String(512))
    source_tool: Mapped[str] = mapped_column(String(64))
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)

    scan: Mapped[ScanRow] = relationship(back_populates="assets")

    __table_args__ = (
        UniqueConstraint("scan_id", "asset_type", "value", name="uq_asset_scan_type_value"),
        Index("ix_assets_value", "value"),
    )


# -----------------------------------------------------------------------------
class FindingRow(Base):
    """A potential vulnerability or security observation."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    source_tool: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.OPEN.value)
    confidence: Mapped[int] = mapped_column(default=100)
    discovered_at: Mapped[datetime] = mapped_column(UTCDateTime)

    scan: Mapped[ScanRow] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_severity_status", "severity", "status"),)


# -----------------------------------------------------------------------------
class ReportRow(Base):
    """Generated artefact (HTML / PDF / JSON) for a scan."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    fmt: Mapped[str] = mapped_column(String(16))  # html | pdf | json
    path: Mapped[str] = mapped_column(String(1024))
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime)

    scan: Mapped[ScanRow] = relationship(back_populates="reports")


# -----------------------------------------------------------------------------
class AnalysisReportRow(Base):
    """LLM analysis report produced by the analysis engine (Phase 3)."""

    __tablename__ = "analysis_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    report_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime)
