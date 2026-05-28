"""Pydantic domain models shared across agents, tools, and persistence.

These are **runtime** value objects. Database rows live in
:mod:`vanguard_x.db.schema` (SQLAlchemy). The two layers are converted at
the repository boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------
class Severity(StrEnum):
    """OWASP-aligned finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    """Lifecycle of a single scan run."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SCOPE_VIOLATION = "scope_violation"


class AssetType(StrEnum):
    """Kinds of assets a recon run can yield."""

    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    TECHNOLOGY = "technology"
    URL = "url"


class FindingStatus(StrEnum):
    """Lifecycle of a finding."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


# -----------------------------------------------------------------------------
# Core models
# -----------------------------------------------------------------------------
def _utcnow() -> datetime:
    """Timezone-aware UTC ``datetime.now`` — used as a default factory."""
    return datetime.now(UTC)


class Asset(BaseModel):
    """A discovered asset (host, port, subdomain, technology, ...)."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    asset_type: AssetType
    value: str = Field(..., min_length=1, max_length=512)
    extra: dict[str, Any] = Field(default_factory=dict)
    source_tool: str = Field(..., min_length=1, max_length=64)
    discovered_at: datetime = Field(default_factory=_utcnow)

    def dedupe_key(self) -> tuple[str, str]:
        """Stable identity for asset deduplication across tools."""
        return (self.asset_type.value, self.value.lower())


class Finding(BaseModel):
    """A potential vulnerability or security observation."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    title: str = Field(..., min_length=1, max_length=512)
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    cve: str | None = Field(default=None, max_length=32)
    source_tool: str = Field(..., min_length=1, max_length=64)
    asset_value: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    confidence: int = Field(default=100, ge=0, le=100)
    discovered_at: datetime = Field(default_factory=_utcnow)


class ToolRunResult(BaseModel):
    """Structured output of a single tool invocation."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    target: str
    started_at: datetime
    completed_at: datetime
    return_code: int
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    raw_excerpt: str = Field(
        default="",
        description="First ~2KB of stdout for debugging. Never the full dump.",
    )

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()


class ScanSummary(BaseModel):
    """High-level result of an agent run, suitable for notifications."""

    model_config = ConfigDict(extra="forbid")

    scan_id: int
    target: str
    scope_label: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime | None = None
    asset_count: int = 0
    finding_count: int = 0
    findings_by_severity: dict[Severity, int] = Field(default_factory=dict)
    error: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


# -----------------------------------------------------------------------------
# Change detection (Month 2)
# -----------------------------------------------------------------------------
class AssetIdentity(BaseModel):
    """Stable identity of an asset across scans.

    Two assets are considered "the same" iff their ``(asset_type, value)``
    pair matches (case-insensitive on ``value``). ``source_tool`` and
    ``extra`` are carried for context in alerts but never for equality.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_type: AssetType
    value: str = Field(..., min_length=1, max_length=512)
    source_tool: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.asset_type.value, self.value.lower())


class ScanDiff(BaseModel):
    """Result of comparing a scan against the previous completed scan.

    ``previous_scan_id is None`` means this is the baseline scan for the
    target — every asset is new by definition, but operators usually do
    not want a "1432 new assets" pager at midnight, so notifiers should
    treat ``is_baseline`` specially.
    """

    model_config = ConfigDict(extra="forbid")

    scan_id: int
    target: str
    previous_scan_id: int | None
    new: list[AssetIdentity] = Field(default_factory=list)
    removed: list[AssetIdentity] = Field(default_factory=list)

    @property
    def is_baseline(self) -> bool:
        return self.previous_scan_id is None

    @property
    def total_changes(self) -> int:
        return len(self.new) + len(self.removed)

    @property
    def has_changes(self) -> bool:
        return self.total_changes > 0
