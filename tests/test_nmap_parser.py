"""Tests for the Nmap XML parser and command construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from vanguard_x.models import AssetType
from vanguard_x.tools.nmap import NmapWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nmap(fake_runner, scope):
    return NmapWrapper(fake_runner, scope)


def test_argv_uses_safe_defaults(nmap):
    argv = nmap.build_argv("example.com")
    assert argv[0] == "nmap"
    assert "-sT" in argv  # no root needed
    assert "-Pn" in argv
    assert "-oX" in argv
    assert argv[-1] == "example.com"
    # max-rate guard is present (anti-DoS safety)
    assert "--max-rate" in argv


def test_argv_overrides(fake_runner, scope):
    custom = ("nmap", "-sS", "-A", "-oX", "-")
    wrapper = NmapWrapper(fake_runner, scope, argv_overrides=custom)
    argv = wrapper.build_argv("example.com")
    assert argv == (*custom, "example.com")


# -----------------------------------------------------------------------------
def test_parse_known_xml_yields_expected_assets(nmap):
    from tests.conftest import make_command_result

    xml = (FIXTURES / "nmap_sample.xml").read_text()
    result = make_command_result(stdout=xml)
    parsed = nmap.parse("example.com", result)

    assert parsed.tool == "nmap"
    assert parsed.target == "example.com"
    assert parsed.return_code == 0

    by_type: dict[AssetType, list] = {}
    for a in parsed.assets:
        by_type.setdefault(a.asset_type, []).append(a)

    # exactly one HOST (deduped at agent level later)
    assert len(by_type[AssetType.HOST]) == 1
    assert by_type[AssetType.HOST][0].value == "93.184.216.34"

    # two open ports (80, 443) — the "closed" one is filtered out
    ports = sorted(a.extra["port"] for a in by_type[AssetType.PORT])
    assert ports == [80, 443]

    # service entries carry product / version metadata
    services = by_type[AssetType.SERVICE]
    assert any(s.extra["product"] == "nginx" and s.extra["version"] == "1.18.0" for s in services)

    # technology entries combine product + version
    techs = [a.value for a in by_type[AssetType.TECHNOLOGY]]
    assert "nginx 1.18.0" in techs


def test_parse_empty_stdout_yields_no_assets(nmap):
    from tests.conftest import make_command_result

    parsed = nmap.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []
    assert parsed.tool == "nmap"


def test_parse_malformed_xml_does_not_raise(nmap):
    from tests.conftest import make_command_result

    parsed = nmap.parse("example.com", make_command_result(stdout="<not-xml"))
    assert parsed.assets == []


def test_parse_xml_without_open_ports_only_emits_host(nmap):
    from tests.conftest import make_command_result

    xml = """<?xml version="1.0"?><nmaprun><host>
        <status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports>
    </host></nmaprun>"""
    parsed = nmap.parse("1.2.3.4", make_command_result(stdout=xml))
    types = {a.asset_type for a in parsed.assets}
    assert types == {AssetType.HOST}


# -----------------------------------------------------------------------------
async def test_run_invokes_runner_and_returns_result(nmap, fake_runner):
    from tests.conftest import make_command_result

    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )
    result = await nmap.run("example.com")
    assert result.succeeded
    assert result.assets, "expected non-empty assets from fixture XML"
    assert fake_runner.calls, "runner should have been invoked"


async def test_run_blocks_unauthorized_target(nmap):
    from vanguard_x.core.scope import ScopeViolation

    with pytest.raises(ScopeViolation):
        await nmap.run("evil.com")
