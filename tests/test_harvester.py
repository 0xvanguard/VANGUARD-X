"""Tests for theHarvester wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from vanguard_x.models import AssetType
from vanguard_x.tools.harvester import HarvesterWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def harvester(fake_runner, scope):
    return HarvesterWrapper(fake_runner, scope)


def test_argv_passes_target_and_sources(harvester):
    argv = harvester.build_argv("example.com")
    assert argv[0] == "theHarvester"
    assert "-d" in argv
    assert "example.com" in argv
    assert "-b" in argv


def test_parse_extracts_in_scope_subdomains_and_emails(harvester):
    from tests.conftest import make_command_result

    text = (FIXTURES / "harvester_sample.txt").read_text()
    result = make_command_result(stdout=text)
    parsed = harvester.parse("example.com", result)

    by_type: dict[AssetType, list] = {}
    for a in parsed.assets:
        by_type.setdefault(a.asset_type, []).append(a)

    sub_values = {a.value for a in by_type.get(AssetType.SUBDOMAIN, [])}
    assert {"www.example.com", "api.example.com", "mail.example.com"} <= sub_values
    # apex itself must NOT be reported as a subdomain
    assert "example.com" not in sub_values

    email_values = {a.value for a in by_type.get(AssetType.EMAIL, [])}
    assert "admin@example.com" in email_values
    assert "security@example.com" in email_values

    # noise from the fixture must be filtered out
    assert "[email protected]" not in email_values
    assert "google.com" not in sub_values
    assert "attacker.com" not in sub_values

    # public IPs captured, placeholders dropped
    ip_values = {a.value for a in by_type.get(AssetType.HOST, [])}
    assert "93.184.216.34" in ip_values
    assert not any(ip.startswith(("0.", "127.", "255.")) for ip in ip_values)


def test_parse_empty_input_yields_no_assets(harvester):
    from tests.conftest import make_command_result

    parsed = harvester.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []
