"""End-to-end tests for the RECON agent.

The agent owns the safety-critical orchestration: scope check first,
DB persistence, partial-result tolerance on tool failures, and
scope-violation status when an unauthorised target is requested.

These tests inject :class:`FakeRunner` instances so the network is
never touched.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from vanguard_x.agents.recon import ReconAgent
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.models import ScanStatus
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper

FIXTURES = Path(__file__).parent / "fixtures"


def _silent_notifier() -> TelegramNotifier:
    """A notifier that records calls without performing real network I/O."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TelegramNotifier(bot_token="t", chat_id="c", client=client)


def _build_agent(*, fake_runner, scope, repository, notifier):
    nmap = NmapWrapper(fake_runner, scope, timeout=5)
    harvester = HarvesterWrapper(fake_runner, scope, timeout=5)
    return ReconAgent(
        nmap=nmap,
        harvester=harvester,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )


# -----------------------------------------------------------------------------
async def test_full_pipeline_persists_and_notifies(fake_runner, scope, repository):
    from tests.conftest import make_command_result

    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )
    fake_runner.responses["theHarvester"] = make_command_result(
        stdout=(FIXTURES / "harvester_sample.txt").read_text()
    )

    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )
    summary = await agent.run("example.com")

    assert summary.status is ScanStatus.DONE
    assert summary.target == "example.com"
    # nmap fixture: 1 host + 2 ports + 2 services + 2 tech = 7
    # harvester fixture: 3 subdomains + 2 emails + 1 IP (one collides w/ nmap host)
    assert summary.asset_count >= 7
    await notifier.aclose()


async def test_scope_violation_blocks_scan(fake_runner, repository):
    """A target outside the authorised list must never reach the runner."""
    scope = ScopeEnforcer(["allowed.com"])
    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )

    with pytest.raises(ScopeViolation):
        await agent.run("evil.com")

    # No CommandRunner call must have been issued.
    assert fake_runner.calls == []
    await notifier.aclose()


async def test_scope_violation_after_scan_creation_records_status(
    fake_runner, repository, monkeypatch
):
    """If a tool wrapper raises ScopeViolation mid-flight, status reflects it."""
    scope = ScopeEnforcer(["example.com"])
    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )

    # Force the nmap wrapper to raise a ScopeViolation as if the target had been
    # mutated mid-flight (defence in depth).
    async def _raise(self, target):
        raise ScopeViolation(target, ["example.com"])

    monkeypatch.setattr(NmapWrapper, "run", _raise)

    with pytest.raises(ScopeViolation):
        await agent.run("example.com")

    summary = await repository.scan_summary(1)
    assert summary.status is ScanStatus.SCOPE_VIOLATION
    await notifier.aclose()


async def test_partial_results_when_one_tool_fails(fake_runner, scope, repository, monkeypatch):
    from tests.conftest import make_command_result

    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )

    # Make theHarvester explode at .run() time
    async def _explode(self, target):
        raise RuntimeError("network down")

    monkeypatch.setattr(HarvesterWrapper, "run", _explode)

    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )
    summary = await agent.run("example.com")

    # Scan still finishes with nmap's assets.
    assert summary.status is ScanStatus.DONE
    assert summary.asset_count >= 1
    await notifier.aclose()


async def test_unexpected_error_marks_scan_failed(fake_runner, scope, repository, monkeypatch):
    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner,
        scope=scope,
        repository=repository,
        notifier=notifier,
    )

    # The repository helper used after both tools is persist_assets — break it.
    async def _explode(scan_id, assets):
        raise RuntimeError("disk full")

    monkeypatch.setattr(repository, "persist_assets", _explode)

    with pytest.raises(RuntimeError):
        await agent.run("example.com")

    summary = await repository.scan_summary(1)
    assert summary.status is ScanStatus.FAILED
    assert summary.error and "disk full" in summary.error
    await notifier.aclose()
