"""Tests for the WhatWeb wrapper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vanguard_x.core.scope import ScopeViolation
from vanguard_x.models import AssetType
from vanguard_x.tools.whatweb import WhatWebWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def whatweb(fake_runner, scope):
    return WhatWebWrapper(fake_runner, scope)


def test_argv_includes_json_stdout_and_url_prefix(whatweb):
    argv = whatweb.build_argv("example.com")
    assert argv[0] == "whatweb"
    assert "--log-json=/dev/stdout" in argv
    assert "--color=never" in argv
    assert "--quiet" in argv
    assert any("--aggression=" in a for a in argv)
    # Hostname auto-prefixed with http://
    assert argv[-1] == "http://example.com"


def test_argv_keeps_user_provided_scheme(whatweb):
    argv = whatweb.build_argv("https://example.com")
    assert argv[-1] == "https://example.com"


def test_invalid_aggression_rejected(fake_runner, scope):
    with pytest.raises(ValueError):
        WhatWebWrapper(fake_runner, scope, aggression=2)


def test_parse_extracts_technology_and_host(whatweb):
    from tests.conftest import make_command_result

    text = (FIXTURES / "whatweb_sample.json").read_text()
    parsed = whatweb.parse("example.com", make_command_result(stdout=text))

    by_type: dict[AssetType, list] = {}
    for a in parsed.assets:
        by_type.setdefault(a.asset_type, []).append(a)

    # 1 HOST asset carrying the HTTP status
    hosts = by_type[AssetType.HOST]
    assert len(hosts) == 1
    assert hosts[0].extra["http_status"] == 200

    # 5 plugin entries -> 5 TECHNOLOGY assets
    techs = {a.value for a in by_type[AssetType.TECHNOLOGY]}
    assert "nginx 1.18.0" in techs
    assert "JQuery 3.6.0" in techs
    # Plugin without version is just the plugin name
    assert "HTML5" in techs
    assert "Cookies" in techs


def test_parse_handles_jsonl_format(whatweb):
    from tests.conftest import make_command_result

    record = {
        "target": "http://api.example.com",
        "http_status": 404,
        "plugins": {"nginx": [{"version": ["1.20.0"]}]},
    }
    text = json.dumps(record)
    parsed = whatweb.parse("api.example.com", make_command_result(stdout=text))
    techs = [a.value for a in parsed.assets if a.asset_type is AssetType.TECHNOLOGY]
    assert "nginx 1.20.0" in techs


def test_parse_empty_input(whatweb):
    from tests.conftest import make_command_result

    parsed = whatweb.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []


def test_parse_malformed_json_does_not_raise(whatweb):
    from tests.conftest import make_command_result

    parsed = whatweb.parse(
        "example.com",
        make_command_result(stdout="<html>oops not json</html>"),
    )
    assert parsed.assets == []


def test_parse_missing_plugins_key(whatweb):
    from tests.conftest import make_command_result

    text = '[{"target":"http://x","http_status":200}]'
    parsed = whatweb.parse("example.com", make_command_result(stdout=text))
    # HOST emitted, no TECHNOLOGY entries
    types = {a.asset_type for a in parsed.assets}
    assert types == {AssetType.HOST}


async def test_run_blocks_unauthorized_target(whatweb):
    with pytest.raises(ScopeViolation):
        await whatweb.run("evil.com")
