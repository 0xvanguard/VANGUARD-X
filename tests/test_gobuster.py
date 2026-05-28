"""Tests for the Gobuster wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from vanguard_x.core.scope import ScopeViolation
from vanguard_x.models import AssetType
from vanguard_x.tools.gobuster import GobusterWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def gobuster(fake_runner, scope):
    return GobusterWrapper(fake_runner, scope)


def test_argv(gobuster):
    argv = gobuster.build_argv("example.com")
    assert argv == (
        "gobuster",
        "dir",
        "-u",
        "http://example.com",
        "-w",
        "/wordlists/common.txt",
        "-q",
        "-n",
        "--no-error",
        "-t",
        "50",
    )


def test_argv_custom_wordlist(fake_runner, scope):
    wrapper = GobusterWrapper(fake_runner, scope, wordlist_path="/custom/wordlist.txt")
    argv = wrapper.build_argv("example.com")
    assert "-w" in argv
    idx = argv.index("-w")
    assert argv[idx + 1] == "/custom/wordlist.txt"


def test_parse_extracts_urls(gobuster):
    from tests.conftest import make_command_result

    text = (FIXTURES / "gobuster_sample.txt").read_text()
    result = make_command_result(stdout=text)
    parsed = gobuster.parse("example.com", result)

    assert parsed.tool == "gobuster"
    assert parsed.target == "example.com"
    assert len(parsed.assets) == 18

    # All assets are URL type
    assert all(a.asset_type is AssetType.URL for a in parsed.assets)

    # Check a specific asset
    admin = next(a for a in parsed.assets if "/admin" in a.value)
    assert admin.value == "http://example.com/admin"
    assert admin.extra["status_code"] == 200
    assert admin.extra["size"] == 1234
    assert admin.source_tool == "gobuster"


def test_parse_empty(gobuster):
    from tests.conftest import make_command_result

    parsed = gobuster.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []
    assert parsed.tool == "gobuster"


def test_parse_malformed_lines_skipped(gobuster):
    from tests.conftest import make_command_result

    stdout = "random garbage line\n\nnot a valid result\n/valid (Status: 200) [Size: 100]\n"
    parsed = gobuster.parse("example.com", make_command_result(stdout=stdout))
    assert len(parsed.assets) == 1
    assert parsed.assets[0].value == "http://example.com/valid"


async def test_scope_violation(gobuster):
    with pytest.raises(ScopeViolation):
        await gobuster.run("evil.com")


async def test_run_invokes_runner(gobuster, fake_runner):
    from tests.conftest import make_command_result

    fake_runner.responses["gobuster"] = make_command_result(
        stdout=(FIXTURES / "gobuster_sample.txt").read_text()
    )
    result = await gobuster.run("example.com")
    assert result.tool == "gobuster"
    assert result.assets, "expected non-empty assets from fixture"
    assert fake_runner.calls
