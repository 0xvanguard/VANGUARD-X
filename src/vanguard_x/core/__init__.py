"""Cross-cutting infrastructure: scope enforcement, command execution.

These modules are dependencies of agents and tool wrappers but never
depend on them in turn — keeping the dependency graph one-way.
"""

from __future__ import annotations

from vanguard_x.core.runners import (
    CommandResult,
    CommandRunner,
    DockerExecRunner,
    LocalRunner,
    ToolExecutionError,
    build_runner,
)
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation

__all__ = [
    "CommandResult",
    "CommandRunner",
    "DockerExecRunner",
    "LocalRunner",
    "ScopeEnforcer",
    "ScopeViolation",
    "ToolExecutionError",
    "build_runner",
]
