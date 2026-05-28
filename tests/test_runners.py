"""Tests for command-runner abstractions."""

from __future__ import annotations

import pytest

from vanguard_x.config import Settings, ToolRunnerKind
from vanguard_x.core.runners import (
    DockerExecRunner,
    LocalRunner,
    ToolExecutionError,
    build_runner,
)


# -----------------------------------------------------------------------------
# LocalRunner — exercises the real subprocess path.
# -----------------------------------------------------------------------------
async def test_local_runner_echo_succeeds():
    runner = LocalRunner()
    result = await runner.run(["/bin/echo", "vanguard-x"], timeout=10)

    assert result.succeeded
    assert result.return_code == 0
    assert result.stdout.strip() == "vanguard-x"
    assert result.duration_seconds >= 0


async def test_local_runner_nonzero_exit():
    runner = LocalRunner()
    result = await runner.run(["/bin/sh", "-c", "exit 7"], timeout=10)
    assert result.return_code == 7
    assert not result.succeeded


async def test_local_runner_timeout():
    runner = LocalRunner()
    result = await runner.run(["/bin/sh", "-c", "sleep 5"], timeout=0.2)
    assert result.timed_out
    assert "TIMEOUT" in result.stderr
    assert not result.succeeded


async def test_local_runner_missing_binary():
    runner = LocalRunner()
    with pytest.raises(ToolExecutionError):
        await runner.run(["/no/such/binary/__vanguardx__"], timeout=5)


async def test_local_runner_rejects_empty_argv():
    runner = LocalRunner()
    with pytest.raises(ValueError):
        await runner.run([], timeout=5)


async def test_local_runner_passes_stdin():
    runner = LocalRunner()
    result = await runner.run(["/bin/cat"], timeout=10, stdin="hello-stdin\n")
    assert result.succeeded
    assert "hello-stdin" in result.stdout


# -----------------------------------------------------------------------------
# DockerExecRunner — uses a fake inner runner.
# -----------------------------------------------------------------------------
async def test_docker_exec_wraps_command(fake_runner):
    runner = DockerExecRunner("vanguardx-nmap", inner=fake_runner)
    await runner.run(["nmap", "--version"], timeout=10)
    sent_argv, _, _ = fake_runner.calls[-1]
    assert sent_argv == ("docker", "exec", "-i", "vanguardx-nmap", "nmap", "--version")


def test_docker_exec_rejects_invalid_container_name():
    with pytest.raises(ValueError):
        DockerExecRunner("bad name with spaces")


# -----------------------------------------------------------------------------
# build_runner factory.
# -----------------------------------------------------------------------------
def test_build_runner_local():
    settings = Settings(authorized_targets="example.com", tool_runner=ToolRunnerKind.LOCAL)
    runner = build_runner(settings, container="vanguardx-nmap")
    assert isinstance(runner, LocalRunner)


def test_build_runner_docker_exec():
    settings = Settings(authorized_targets="example.com", tool_runner=ToolRunnerKind.DOCKER_EXEC)
    runner = build_runner(settings, container="vanguardx-nmap")
    assert isinstance(runner, DockerExecRunner)


def test_build_runner_docker_exec_requires_container():
    settings = Settings(authorized_targets="example.com", tool_runner=ToolRunnerKind.DOCKER_EXEC)
    with pytest.raises(ValueError):
        build_runner(settings, container=None)


# -----------------------------------------------------------------------------
def test_command_result_display_is_shell_safe():
    from tests.conftest import make_command_result

    res = make_command_result(argv=("nmap", "-oX", "-", "example.com; rm"))
    rendered = res.display_command()
    assert "rm" in rendered
    # Each shell-special character must be quoted/escaped.
    assert "'example.com; rm'" in rendered or '"example.com; rm"' in rendered
