"""Tool wrappers — thin adapters around external pentest binaries.

Every wrapper:

1. Asks the :class:`~vanguard_x.core.scope.ScopeEnforcer` to authorise the
   target before constructing any command line.
2. Delegates execution to a :class:`~vanguard_x.core.runners.CommandRunner`,
   so the same code path serves local subprocess **and** ``docker exec``.
3. Returns a strongly-typed :class:`~vanguard_x.models.ToolRunResult` —
   callers never see raw bytes.

The :class:`BaseTool` template enforces this contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import ToolRunResult

_log = get_logger(__name__)


class BaseTool(ABC):
    """Common scaffolding for all tool wrappers."""

    #: human-readable identifier used in logs, DB rows, telemetry
    name: str = "base"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 600.0,
    ) -> None:
        self._runner = runner
        self._scope = scope
        self._timeout = timeout

    # ------------------------------------------------------------------
    @abstractmethod
    def build_argv(self, target: str) -> tuple[str, ...]:
        """Return the ``argv`` for the given target."""

    @abstractmethod
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        """Convert a :class:`CommandResult` into a structured :class:`ToolRunResult`."""

    # ------------------------------------------------------------------
    async def run(self, target: str) -> ToolRunResult:
        """Authorise the target, execute the tool, return parsed output.

        Always returns a :class:`ToolRunResult`; never raises on tool failure
        — callers inspect ``succeeded`` / ``return_code`` instead. Scope
        violations and runner-level errors do propagate.
        """
        self._scope.assert_authorized(target)
        argv = self.build_argv(target)

        _log.info("tool.start", tool=self.name, target=target, argv=argv)
        cmd_result = await self._runner.run(argv, timeout=self._timeout)
        _log.info(
            "tool.done",
            tool=self.name,
            target=target,
            rc=cmd_result.return_code,
            duration=cmd_result.duration_seconds,
            timed_out=cmd_result.timed_out,
        )

        try:
            return self.parse(target, cmd_result)
        except Exception as exc:
            # Parser failure must not lose the run record.
            _log.error("tool.parse_failed", tool=self.name, target=target, error=str(exc))
            return ToolRunResult(
                tool=self.name,
                target=target,
                started_at=cmd_result.started_at,
                completed_at=cmd_result.completed_at or datetime.now(UTC),
                return_code=cmd_result.return_code,
                raw_excerpt=cmd_result.stdout[:2048],
            )


__all__ = ["BaseTool"]
