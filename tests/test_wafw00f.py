"""Tests for the wafw00f wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vanguard_x.core.scope import ScopeViolation
from vanguard_x.models import AssetType
from vanguard_x.tools.wafw00f import WafW00fWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def wafw00f(fake_runner, scope):
    return WafW00fWrapper(fake_runner, scope)


def test_argv_uses_json_to_stdout_and_url_prefix(wafw00f):
    argv = wafw00f.build_argv("example.com")
    assert argv[0] == "wafw00f"
    assert "-o" in argv and "/dev/stdout" in argv
    assert "-f" in argv and "json" in argv
    assert argv[-1] == "http://example.com"


def test_parse_emits_waf_technology_when_detected(wafw00f):
    from tests.conftest import make_command_result

    text = (FIXTURES / "wafw00f_sample.json").read_text()
    parsed = wafw00f.parse("example.com", make_command_result(stdout=text))

    assert len(parsed.assets) == 1
    waf = parsed.assets[0]
    assert waf.asset_type is AssetType.TECHNOLOGY
    assert waf.value == "WAF: Cloudflare"
    assert waf.extra["manufacturer"] == "Cloudflare Inc."


def test_parse_skips_when_not_detected(wafw00f):
    from tests.conftest import make_command_result

    text = json.dumps([{"url": "http://x", "detected": False, "firewall": "None"}])
    parsed = wafw00f.parse("example.com", make_command_result(stdout=text))
    assert parsed.assets == []


def test_parse_skips_generic_or_none_firewall(wafw00f):
    from tests.conftest import make_command_result

    text = json.dumps(
        [
            {"url": "http://x", "detected": True, "firewall": "Generic"},
            {"url": "http://y", "detected": True, "firewall": "none"},
            {"url": "http://z", "detected": True, "firewall": ""},
        ]
    )
    parsed = wafw00f.parse("example.com", make_command_result(stdout=text))
    assert parsed.assets == []


def test_parse_dict_shape_supported(wafw00f):
    from tests.conftest import make_command_result

    text = json.dumps(
        {"url": "http://x", "detected": True, "firewall": "Akamai", "manufacturer": "Akamai Inc."}
    )
    parsed = wafw00f.parse("example.com", make_command_result(stdout=text))
    assert len(parsed.assets) == 1
    assert parsed.assets[0].value == "WAF: Akamai"


def test_parse_empty_or_malformed_input(wafw00f):
    from tests.conftest import make_command_result

    assert wafw00f.parse("example.com", make_command_result(stdout="")).assets == []
    assert wafw00f.parse("example.com", make_command_result(stdout="<not json>")).assets == []


async def test_run_blocks_unauthorized_target(wafw00f):
    with pytest.raises(ScopeViolation):
        await wafw00f.run("evil.com")
