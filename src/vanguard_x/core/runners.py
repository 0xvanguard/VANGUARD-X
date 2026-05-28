"""Command execution abstractions for tool wrappers.

A :class:`CommandRunner` knows **how** to invoke an external binary; tool
wrappers know **which** binary and **how to parse its output**. This
separation lets us:

- Run tools locally (default in dev) via :class:`LocalRunner`.
- Run tools inside hardened, isolated containers via :class:`DockerExecRunner`
  (default in production ``docker compose`` deployment).
- Inject deterministic fakes in tests, never touching the real network.

Every runner enforces a timeout and returns a structured
:class:`CommandResult` — never raw byte streams.
"""

from __future__ import annotations

import asyncio
import contextlib
import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from vanguard_x.config import Settings, ToolRunnerKind
from vanguard_x.logging_setup import get_logger

_log = get_logger(__name__)


class ToolExecutionError(RuntimeError):
    """Raised when a tool invocation fails irrecoverably (timeout, missing binary)."""


@dataclass(frozen=True)
class CommandResult:
    """Structured outcome of a single command invocation."""

    argv: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    started_at: datetime
    completed_at: datetime
    timed_out: bool = False

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    def display_command(self) -> str:
        """Shell-safe quoted form of the command — for logs only."""
        return " ".join(shlex.quote(a) for a in self.argv)


# -----------------------------------------------------------------------------
class CommandRunner(ABC):
    """Abstract base for command execution strategies."""

    @abstractmethod
    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: str | None = None,
    ) -> CommandResult:
        """Execute ``argv`` and return the structured outcome."""


# -----------------------------------------------------------------------------
class LocalRunner(CommandRunner):
    """Run commands as direct subprocesses on the current host / container."""

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: str | None = None,
    ) -> CommandResult:
        argv_t = tuple(argv)
        if not argv_t:
            raise ValueError("argv must be non-empty")

        started_at = datetime.now(UTC)
        _log.debug("command.start", argv=argv_t, runner="local", timeout=timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv_t,
                stdin=asyncio.subprocess.PIPE if stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ToolExecutionError(
                f"binary not found: {argv_t[0]!r}. "
                "Install the tool locally or use TOOL_RUNNER=docker_exec."
            ) from exc

        stdin_bytes = stdin.encode() if stdin is not None else None
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout
            )
        except TimeoutError:
            proc.kill()
            with contextlib.suppress(BaseException):
                await proc.wait()
            completed_at = datetime.now(UTC)
            _log.warning("command.timeout", argv=argv_t, timeout=timeout)
            return CommandResult(
                argv=argv_t,
                return_code=-1,
                stdout="",
                stderr=f"TIMEOUT after {timeout}s",
                started_at=started_at,
                completed_at=completed_at,
                timed_out=True,
            )

        completed_at = datetime.now(UTC)
        result = CommandResult(
            argv=argv_t,
            return_code=int(proc.returncode or 0),
            stdout=stdout_b.decode(errors="replace"),
            stderr=stderr_b.decode(errors="replace"),
            started_at=started_at,
            completed_at=completed_at,
        )
        _log.debug(
            "command.done",
            argv=argv_t,
            rc=result.return_code,
            duration=result.duration_seconds,
        )
        return result


# -----------------------------------------------------------------------------
class DockerExecRunner(CommandRunner):
    """Run commands inside a long-running, named container via ``docker exec``.

    Production deployments build hardened images for each tool and let the
    core orchestrator exec into them with a read-only docker socket mount.
    """

    def __init__(self, container: str, *, inner: CommandRunner | None = None) -> None:
        if not container or any(c.isspace() for c in container):
            raise ValueError(f"invalid container name: {container!r}")
        self._container = container
        self._inner: CommandRunner = inner or LocalRunner()

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        stdin: str | None = None,
    ) -> CommandResult:
        wrapped = ("docker", "exec", "-i", self._container, *argv)
        return await self._inner.run(wrapped, timeout=timeout, stdin=stdin)


# -----------------------------------------------------------------------------
def build_runner(settings: Settings, *, container: str | None = None) -> CommandRunner:
    """Construct the configured runner for a given tool container.

    ``container`` is only consulted when ``settings.tool_runner`` is
    :attr:`ToolRunnerKind.DOCKER_EXEC`.
    """
    if settings.tool_runner is ToolRunnerKind.LOCAL:
        return LocalRunner()
    if settings.tool_runner is ToolRunnerKind.DOCKER_EXEC:
        if not container:
            raise ValueError("docker_exec runner requires a container name")
        return DockerExecRunner(container)
    raise ValueError(f"unsupported tool runner: {settings.tool_runner!r}")
