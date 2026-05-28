"""Continuous monitoring scheduler.

Wraps APScheduler's :class:`AsyncIOScheduler` so the ReconAgent can be
re-fired at a fixed interval per target. Built specifically for the
``vanguard-x monitor`` CLI subcommand introduced in Month 2.

Design properties:

- One :class:`AsyncIOScheduler` instance, one job per target. Job ids are
  stable (``recon-<target>``) so subsequent ``start()`` calls replace
  rather than duplicate.
- ``coalesce=True`` + ``max_instances=1`` means we never queue overlapping
  runs. If a 24h-cadence scan takes 26h, the second invocation is skipped
  rather than concurrent — the right default for pentest tooling.
- ``next_run_time=now`` forces the first scan immediately on ``start()``;
  subsequent runs follow the interval.
- ``shutdown(wait=True)`` lets in-flight scans finish before the process
  exits, preventing torn DB writes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from vanguard_x.agents.recon import ReconAgent
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import ScanSummary

_log = get_logger(__name__)


# Type of the optional callback fired after each successful scan.
ScanCallback = Callable[[ScanSummary], Awaitable[None]]


class ContinuousMonitor:
    """Schedule periodic ReconAgent runs against a list of targets."""

    def __init__(
        self,
        agent: ReconAgent,
        targets: Iterable[str],
        *,
        interval: timedelta,
        scope_label: str = "external",
        on_scan_complete: ScanCallback | None = None,
    ) -> None:
        targets_list = [t.strip() for t in targets if t and t.strip()]
        if not targets_list:
            raise ValueError("at least one target is required")
        if interval.total_seconds() <= 0:
            raise ValueError("interval must be positive")

        self._agent = agent
        self._targets: tuple[str, ...] = tuple(dict.fromkeys(targets_list))  # dedupe, keep order
        self._interval = interval
        self._scope_label = scope_label
        self._scheduler = AsyncIOScheduler(timezone=UTC)
        self._on_scan_complete = on_scan_complete

    # ------------------------------------------------------------------
    @property
    def targets(self) -> tuple[str, ...]:
        return self._targets

    @property
    def is_running(self) -> bool:
        return bool(self._scheduler.running)

    # ------------------------------------------------------------------
    def start(self) -> None:
        """Register one job per target and start the scheduler."""
        trigger = IntervalTrigger(seconds=self._interval.total_seconds())
        now = datetime.now(UTC)

        for target in self._targets:
            self._scheduler.add_job(
                self._scan_once,
                trigger=trigger,
                kwargs={"target": target},
                id=f"recon-{target}",
                name=f"recon-{target}",
                next_run_time=now,
                coalesce=True,
                max_instances=1,
                replace_existing=True,
                misfire_grace_time=300,
            )
        self._scheduler.start()
        _log.info(
            "monitor.started",
            targets=list(self._targets),
            interval_seconds=self._interval.total_seconds(),
        )

    async def shutdown(self, *, wait: bool = True) -> None:
        """Stop the scheduler; ``wait=True`` lets in-flight scans finish."""
        if not self._scheduler.running:
            return
        self._scheduler.shutdown(wait=wait)
        _log.info("monitor.stopped", targets=list(self._targets))

    async def run_forever(self) -> None:
        """Block until cancelled — typical CLI use after :meth:`start`."""
        try:
            await asyncio.Event().wait()  # Idle until cancelled by signal.
        except asyncio.CancelledError:
            await self.shutdown(wait=True)
            raise

    # ------------------------------------------------------------------
    async def _scan_once(self, *, target: str) -> None:
        """Single scan invocation; absorbs all errors so the schedule survives."""
        try:
            summary = await self._agent.run(target, scope_label=self._scope_label)
        except Exception as exc:
            _log.error("monitor.scan_failed", target=target, error=str(exc))
            return
        if self._on_scan_complete is not None:
            try:
                await self._on_scan_complete(summary)
            except Exception as exc:
                _log.error(
                    "monitor.callback_failed",
                    target=target,
                    error=str(exc),
                )
