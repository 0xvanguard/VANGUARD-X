"""Tests for the Nuclei wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from vanguard_x.core.scope import ScopeViolation
from vanguard_x.models import AssetType, Severity
from vanguard_x.tools.nuclei import NucleiWrapper

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nuclei(fake_runner, scope):
    return NucleiWrapper(fake_runner, scope)


def test_argv(nuclei):
    argv = nuclei.build_argv("example.com")
    assert argv == ("nuclei", "-u", "example.com", "-jsonl", "-silent", "-nc")


def test_parse_extracts_findings_and_assets(nuclei):
    from tests.conftest import make_command_result

    text = (FIXTURES / "nuclei_sample.jsonl").read_text()
    result = make_command_result(stdout=text)
    parsed = nuclei.parse("example.com", result)

    assert parsed.tool == "nuclei"
    assert parsed.target == "example.com"
    assert len(parsed.findings) == 7
    assert len(parsed.assets) == 7

    # Check severities are correctly mapped
    severities = [f.severity for f in parsed.findings]
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities
    assert Severity.MEDIUM in severities
    assert Severity.INFO in severities

    # All assets are URL type
    assert all(a.asset_type is AssetType.URL for a in parsed.assets)

    # Check a specific finding
    log4j = next(f for f in parsed.findings if "Log4j" in f.title)
    assert log4j.severity is Severity.CRITICAL
    assert log4j.cve == "CVE-2021-44228"
    assert log4j.source_tool == "nuclei"
    assert log4j.evidence["template_id"] == "cve-2021-44228-log4j"
    assert log4j.evidence["matcher_name"] == "body-match"
    assert log4j.evidence["matched_at"] == "https://example.com/api/v1/login"


def test_parse_empty(nuclei):
    from tests.conftest import make_command_result

    parsed = nuclei.parse("example.com", make_command_result(stdout=""))
    assert parsed.assets == []
    assert parsed.findings == []
    assert parsed.tool == "nuclei"


def test_parse_malformed_json(nuclei):
    from tests.conftest import make_command_result

    stdout = "not json at all\n{broken json\n\n"
    parsed = nuclei.parse("example.com", make_command_result(stdout=stdout))
    assert parsed.assets == []
    assert parsed.findings == []


async def test_scope_violation(nuclei):
    with pytest.raises(ScopeViolation):
        await nuclei.run("evil.com")


async def test_run_invokes_runner(nuclei, fake_runner):
    from tests.conftest import make_command_result

    fake_runner.responses["nuclei"] = make_command_result(
        stdout=(FIXTURES / "nuclei_sample.jsonl").read_text()
    )
    result = await nuclei.run("example.com")
    assert result.tool == "nuclei"
    assert result.findings, "expected non-empty findings from fixture"
    assert result.assets, "expected non-empty assets from fixture"
    assert fake_runner.calls


def test_cve_extraction(nuclei):
    from tests.conftest import make_command_result

    text = (FIXTURES / "nuclei_sample.jsonl").read_text()
    result = make_command_result(stdout=text)
    parsed = nuclei.parse("example.com", result)

    # Findings with CVEs
    cve_findings = [f for f in parsed.findings if f.cve is not None]
    assert len(cve_findings) >= 3
    cve_values = {f.cve for f in cve_findings}
    assert "CVE-2021-44228" in cve_values
    assert "CVE-2023-22515" in cve_values
    assert "CVE-2024-1234" in cve_values

    # Findings without CVEs should have None
    no_cve_findings = [f for f in parsed.findings if f.cve is None]
    assert len(no_cve_findings) >= 1


def test_unknown_severity_defaults_to_info(nuclei):
    import json

    from tests.conftest import make_command_result

    line = json.dumps({
        "template-id": "custom-check",
        "info": {
            "name": "Custom Check",
            "severity": "unknown_level",
            "description": "Test",
            "reference": [],
        },
        "matched-at": "https://example.com/test",
        "matcher-name": "test",
        "type": "http",
        "host": "https://example.com",
        "timestamp": "2024-01-15T10:00:00Z",
    })
    parsed = nuclei.parse("example.com", make_command_result(stdout=line))
    assert len(parsed.findings) == 1
    assert parsed.findings[0].severity is Severity.INFO
