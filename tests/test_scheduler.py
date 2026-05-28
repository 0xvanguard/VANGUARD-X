"""Tests for the continuous-monitoring scheduler."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from vanguard_x.models import ScanStatus, ScanSummary
from vanguard_x.scheduler import ContinuousMonitor


def _summary(target: str = "example.com") -> ScanSummary:
    now = datetime.now(UTC)
    return ScanSummary(
        scan_id=1,
        target=target,
        scope_label="external",
        status=ScanStatus.DONE,
        started_at=now,
        completed_at=now,
        asset_count=0,
        finding_count=0,
    )


def _fake_agent() -> AsyncMock:
    agent = AsyncMock()
    agent.run.return_value = _summary()
    return agent


# -----------------------------------------------------------------------------
def test_rejects_empty_targets():
    with pytest.raises(ValueError):
        ContinuousMonitor(_fake_agent(), [], interval=timedelta(seconds=1))


def test_rejects_non_positive_interval():
    with pytest.raises(ValueError):
        ContinuousMonitor(_fake_agent(), ["example.com"], interval=timedelta(seconds=0))


def test_dedupe_targets_preserves_order():
    monitor = ContinuousMonitor(
        _fake_agent(),
        ["a.com", "b.com", "a.com", "c.com", "b.com"],
        interval=timedelta(seconds=10),
    )
    assert monitor.targets == ("a.com", "b.com", "c.com")


# -----------------------------------------------------------------------------
async def test_first_scan_runs_immediately_then_periodically():
    """The first scan fires on start; subsequent runs follow the interval."""
    agent = _fake_agent()
    monitor = ContinuousMonitor(
        agent,
        ["example.com"],
        interval=timedelta(milliseconds=120),
    )
    monitor.start()
    try:
        # Wait long enough for ~3 invocations.
        await asyncio.sleep(0.4)
    finally:
        await monitor.shutdown(wait=True)

    # At least 2 invocations: immediate + at least one tick.
    assert agent.run.await_count >= 2
    for call in agent.run.await_args_list:
        assert call.args == ("example.com",) or call.kwargs.get("target") == "example.com"


# -----------------------------------------------------------------------------
async def test_failures_do_not_kill_the_schedule():
    """An exception inside the agent must not stop subsequent runs."""
    agent = AsyncMock()
    agent.run.side_effect = RuntimeError("transient failure")

    monitor = ContinuousMonitor(
        agent,
        ["example.com"],
        interval=timedelta(milliseconds=80),
    )
    monitor.start()
    try:
        await asyncio.sleep(0.3)
    finally:
        await monitor.shutdown(wait=True)

    assert agent.run.await_count >= 2  # kept firing despite the exception


# -----------------------------------------------------------------------------
async def test_callback_fires_after_each_successful_scan():
    agent = _fake_agent()
    received: list[ScanSummary] = []

    async def cb(summary: ScanSummary) -> None:
        received.append(summary)

    monitor = ContinuousMonitor(
        agent,
        ["example.com"],
        interval=timedelta(milliseconds=100),
        on_scan_complete=cb,
    )
    monitor.start()
    try:
        await asyncio.sleep(0.35)
    finally:
        await monitor.shutdown(wait=True)

    assert len(received) >= 2
    assert all(s.target == "example.com" for s in received)


# -----------------------------------------------------------------------------
async def test_callback_errors_are_isolated():
    agent = _fake_agent()

    async def bad_cb(_summary: ScanSummary) -> None:
        raise RuntimeError("callback boom")

    monitor = ContinuousMonitor(
        agent,
        ["example.com"],
        interval=timedelta(milliseconds=80),
        on_scan_complete=bad_cb,
    )
    monitor.start()
    try:
        await asyncio.sleep(0.25)
    finally:
        await monitor.shutdown(wait=True)

    # Callback throwing must not prevent further scans.
    assert agent.run.await_count >= 2


# -----------------------------------------------------------------------------
async def test_shutdown_is_idempotent():
    """``shutdown()`` must never raise, regardless of scheduler state."""
    monitor = ContinuousMonitor(_fake_agent(), ["example.com"], interval=timedelta(seconds=10))
    # Not started yet -> safe no-op.
    await monitor.shutdown()
    assert not monitor.is_running

    monitor.start()
    assert monitor.is_running
    # Use wait=False so we don't block on the immediate job.
    await monitor.shutdown(wait=False)
    # Second shutdown -> safe no-op even if the first one is still settling.
    await monitor.shutdown(wait=False)
