"""Tests for the Subfinder wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from vanguard_x.core.scope import ScopeViolation
from vanguard_x.models import AssetType
from vanguard_x.tools.subfinder import SubfinderWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def subfinder(fake_runner, scope):
    return SubfinderWrapper(fake_runner, scope)


def test_argv_includes_silent_and_json(subfinder):
    argv = subfinder.build_argv("example.com")
    assert argv[0] == "subfinder"
    assert "-d" in argv
    assert "example.com" in argv
    assert "-silent" in argv
    assert "-json" in argv
    assert "-all" in argv  # default constructor enables -all


def test_argv_without_all_sources(fake_runner, scope):
    wrapper = SubfinderWrapper(fake_runner, scope, all_sources=False)
    argv = wrapper.build_argv("example.com")
    assert "-all" not in argv


def test_parse_extracts_in_scope_subdomains_and_dedupes(subfinder):
    from tests.conftest import make_command_result

    text = (FIXTURES / "subfinder_sample.jsonl").read_text()
    result = make_command_result(stdout=text)
    parsed = subfinder.parse("example.com", result)

    values = {a.value for a in parsed.assets}
    # In-scope hosts (apex excluded; case-insensitive dedupe)
    assert {
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "deep.api.example.com",
    } <= values
    # Apex itself never reported as a subdomain
    assert "example.com" not in values
    # Out-of-scope dropped
    assert "attacker.com" not in values
    # Empty / malformed lines silently skipped
    assert all(a.asset_type is AssetType.SUBDOMAIN for a in parsed.assets)
    # Source carried in extra
    api = next(a for a in parsed.assets if a.value == "api.example.com")
    assert api.extra.get("source") == "crtsh"


def test_parse_empty_input(subfinder):
    from tests.conftest import make_command_result

    parsed = subfinder.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []
    assert parsed.tool == "subfinder"


def test_parse_invalid_json_only_yields_no_assets(subfinder):
    from tests.conftest import make_command_result

    parsed = subfinder.parse(
        "example.com",
        make_command_result(stdout="banner line\nanother bogus line\n"),
    )
    assert parsed.assets == []


async def test_run_blocks_unauthorized_target(subfinder):
    with pytest.raises(ScopeViolation):
        await subfinder.run("evil.com")


async def test_run_invokes_runner(subfinder, fake_runner):
    from tests.conftest import make_command_result

    fake_runner.responses["subfinder"] = make_command_result(
        stdout=(FIXTURES / "subfinder_sample.jsonl").read_text()
    )
    result = await subfinder.run("example.com")
    assert result.tool == "subfinder"
    assert result.assets, "expected non-empty assets from fixture"
    assert fake_runner.calls
