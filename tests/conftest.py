"""Shared pytest fixtures for VANGUARD-X."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime

import pytest
import pytest_asyncio

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.db.database import Database, ScanRepository


# ---------------------------------------------------------------------------
class FakeRunner(CommandRunner):
    """In-memory :class:`CommandRunner` for deterministic tests.

    Response lookup uses the first argv element (the binary name) as a key.
    Anything not registered defaults to a successful empty result.
    """

    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.responses: dict[str, CommandResult] = dict(responses or {})
        self.calls: list[tuple[tuple[str, ...], float, str | None]] = []

    async def run(
        self,
        argv,  # type: ignore[no-untyped-def]
        *,
        timeout: float,
        stdin: str | None = None,
    ) -> CommandResult:
        argv_t = tuple(argv)
        self.calls.append((argv_t, timeout, stdin))
        key = argv_t[0] if argv_t else ""
        if key in self.responses:
            stored = self.responses[key]
            return CommandResult(
                argv=argv_t,
                return_code=stored.return_code,
                stdout=stored.stdout,
                stderr=stored.stderr,
                started_at=stored.started_at,
                completed_at=stored.completed_at,
                timed_out=stored.timed_out,
            )
        now = datetime.now(UTC)
        return CommandResult(
            argv=argv_t,
            return_code=0,
            stdout="",
            stderr="",
            started_at=now,
            completed_at=now,
        )


# ---------------------------------------------------------------------------
def make_command_result(
    *,
    stdout: str = "",
    stderr: str = "",
    rc: int = 0,
    argv: Iterable[str] = ("fake",),
    timed_out: bool = False,
) -> CommandResult:
    now = datetime.now(UTC)
    return CommandResult(
        argv=tuple(argv),
        return_code=rc,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        completed_at=now,
        timed_out=timed_out,
    )


# ---------------------------------------------------------------------------
@pytest.fixture
def authorized_targets() -> list[str]:
    return ["example.com", "10.0.0.0/24", "192.168.1.1"]


@pytest.fixture
def scope(authorized_targets: list[str]) -> ScopeEnforcer:
    return ScopeEnforcer(authorized_targets)


@pytest.fixture
def fake_runner() -> FakeRunner:
    return FakeRunner()


# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def database() -> AsyncIterator[Database]:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        yield db
    finally:
        await db.dispose()


@pytest_asyncio.fixture
async def repository(database: Database) -> ScanRepository:
    return ScanRepository(database)


# ---------------------------------------------------------------------------
@pytest.fixture
def event_loop_policy():
    """Use the default event loop policy on all platforms."""
    return asyncio.DefaultEventLoopPolicy()
