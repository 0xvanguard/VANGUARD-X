"""End-to-end tests for the RECON agent.

The agent owns the safety-critical orchestration: scope check first,
DB persistence, partial-result tolerance on tool failures, parallel
execution of all 5 tools, and change-detection integration.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from vanguard_x.agents.recon import ReconAgent
from vanguard_x.core.changes import ChangeDetector
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.models import ScanStatus
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper
from vanguard_x.tools.subfinder import SubfinderWrapper
from vanguard_x.tools.wafw00f import WafW00fWrapper
from vanguard_x.tools.whatweb import WhatWebWrapper

FIXTURES = Path(__file__).parent / "fixtures"


def _silent_notifier() -> TelegramNotifier:
    """A notifier that records calls without performing real network I/O."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TelegramNotifier(bot_token="t", chat_id="c", client=client)


def _build_agent(*, fake_runner, scope, repository, notifier):
    return ReconAgent(
        nmap=NmapWrapper(fake_runner, scope, timeout=5),
        harvester=HarvesterWrapper(fake_runner, scope, timeout=5),
        subfinder=SubfinderWrapper(fake_runner, scope, timeout=5),
        whatweb=WhatWebWrapper(fake_runner, scope, timeout=5),
        wafw00f=WafW00fWrapper(fake_runner, scope, timeout=5),
        scope=scope,
        repository=repository,
        notifier=notifier,
        change_detector=ChangeDetector(repository),
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
    fake_runner.responses["subfinder"] = make_command_result(
        stdout=(FIXTURES / "subfinder_sample.jsonl").read_text()
    )
    fake_runner.responses["whatweb"] = make_command_result(
        stdout=(FIXTURES / "whatweb_sample.json").read_text()
    )
    fake_runner.responses["wafw00f"] = make_command_result(
        stdout=(FIXTURES / "wafw00f_sample.json").read_text()
    )

    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    summary = await agent.run("example.com")

    assert summary.status is ScanStatus.DONE
    assert summary.target == "example.com"
    # All 5 tools contribute, deduped at agent level.
    # Lower bound: nmap (>=7) + harvester (>=4) + subfinder (4) + whatweb (>=5) + wafw00f (1)
    assert summary.asset_count >= 12
    await notifier.aclose()


async def test_tools_run_in_parallel(fake_runner, scope, repository):
    """All 5 tool runs are launched concurrently, not sequentially."""
    from tests.conftest import make_command_result

    started: list[str] = []
    finish_event = asyncio.Event()

    async def slow_run(self, target):
        started.append(self.name)
        # Wait until every tool has started — this only completes if
        # they were truly launched concurrently, not one after another.
        if len(started) < 5:
            await asyncio.wait_for(finish_event.wait(), timeout=2.0)
        else:
            finish_event.set()
        return self.parse(
            target,
            make_command_result(stdout="", argv=(self.name,)),
        )

    monkey = pytest.MonkeyPatch()
    try:
        for cls in (
            NmapWrapper,
            HarvesterWrapper,
            SubfinderWrapper,
            WhatWebWrapper,
            WafW00fWrapper,
        ):
            monkey.setattr(cls, "run", slow_run)

        notifier = _silent_notifier()
        agent = _build_agent(
            fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
        )
        summary = await agent.run("example.com")
    finally:
        monkey.undo()

    assert summary.status is ScanStatus.DONE
    # All 5 tools registered before any finished -> proves concurrency.
    assert set(started) == {"nmap", "theharvester", "subfinder", "whatweb", "wafw00f"}
    await notifier.aclose()


# -----------------------------------------------------------------------------
async def test_scope_violation_blocks_scan(fake_runner, repository):
    """A target outside the authorised list must never reach the runner."""
    scope = ScopeEnforcer(["allowed.com"])
    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
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
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )

    async def _raise(self, target):
        raise ScopeViolation(target, ["example.com"])

    monkeypatch.setattr(NmapWrapper, "run", _raise)

    with pytest.raises(ScopeViolation):
        await agent.run("example.com")

    summary = await repository.scan_summary(1)
    assert summary.status is ScanStatus.SCOPE_VIOLATION
    await notifier.aclose()


async def test_partial_results_when_one_tool_fails(fake_runner, scope, repository, monkeypatch):
    """A failing tool only contributes 0 assets — others still run."""
    from tests.conftest import make_command_result

    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )

    async def _explode(self, target):
        raise RuntimeError("network down")

    monkeypatch.setattr(HarvesterWrapper, "run", _explode)
    monkeypatch.setattr(SubfinderWrapper, "run", _explode)
    monkeypatch.setattr(WhatWebWrapper, "run", _explode)
    monkeypatch.setattr(WafW00fWrapper, "run", _explode)

    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    summary = await agent.run("example.com")

    assert summary.status is ScanStatus.DONE
    assert summary.asset_count >= 1
    await notifier.aclose()


async def test_unexpected_error_marks_scan_failed(fake_runner, scope, repository, monkeypatch):
    notifier = _silent_notifier()
    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )

    async def _explode(scan_id, assets):
        raise RuntimeError("disk full")

    monkeypatch.setattr(repository, "persist_assets", _explode)

    with pytest.raises(RuntimeError):
        await agent.run("example.com")

    summary = await repository.scan_summary(1)
    assert summary.status is ScanStatus.FAILED
    assert summary.error and "disk full" in summary.error
    await notifier.aclose()


# -----------------------------------------------------------------------------
async def test_change_alert_fires_when_diff_has_changes(
    fake_runner, scope, repository, monkeypatch
):
    """Second scan should trigger send_change_alert when assets differ."""
    from tests.conftest import make_command_result

    notifier = _silent_notifier()
    sent: list = []
    original_change = notifier.send_change_alert

    async def spy(diff):
        sent.append(diff)
        return await original_change(diff)

    monkeypatch.setattr(notifier, "send_change_alert", spy)

    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )

    # First scan — baseline. Use nmap fixture.
    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )
    await agent.run("example.com")

    # Second scan — same nmap fixture, but add a brand-new subfinder asset
    # so the diff is non-empty.
    fake_runner.responses["subfinder"] = make_command_result(
        stdout='{"host":"brand-new.example.com","input":"example.com","source":"crtsh"}\n'
    )
    await agent.run("example.com")

    # Baseline should NOT trigger send_change_alert; second scan should.
    assert len(sent) == 1
    diff = sent[0]
    assert not diff.is_baseline
    assert any(a.value == "brand-new.example.com" for a in diff.new)
    await notifier.aclose()


async def test_baseline_scan_does_not_send_change_alert(
    fake_runner, scope, repository, monkeypatch
):
    notifier = _silent_notifier()
    sent: list = []

    async def spy(diff):
        sent.append(diff)
        return True

    monkeypatch.setattr(notifier, "send_change_alert", spy)

    agent = _build_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    await agent.run("example.com")

    # Baseline: agent must not invoke send_change_alert at all.
    assert sent == []
    await notifier.aclose()
