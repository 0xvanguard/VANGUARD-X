"""Persistence layer: SQLAlchemy 2.0 schema + async repository.

Public surface kept small: ``Database`` (engine wrapper), ``ScanRepository``,
and the table classes for ad-hoc queries / migrations.
"""

from __future__ import annotations

from vanguard_x.db.database import Database, ScanRepository
from vanguard_x.db.schema import (
    AssetRow,
    Base,
    FindingRow,
    ReportRow,
    ScanRow,
)

__all__ = [
    "AssetRow",
    "Base",
    "Database",
    "FindingRow",
    "ReportRow",
    "ScanRepository",
    "ScanRow",
]
